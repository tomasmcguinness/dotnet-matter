using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Channels;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace Matter.Core.BTP
{
    class BTPConnection : IConnection
    {
        private readonly BluetoothLEDevice _device;
        private readonly Timer _acknowledgementTimer;
        private GattCharacteristic _readCharacteristic;
        private GattCharacteristic _writeCharacteristic;
        private SemaphoreSlim _writeCharacteristicLock = new SemaphoreSlim(1, 1);
        private ushort _currentAttSize;
        private uint _acknowledgedSequenceCount = 255;
        private uint _receivedSequenceCount = 0;
        private uint _sentSequenceNumber = 0;
        private bool _isConnected;

        private Channel<BTPFrame> _incomingFrameChannel = Channel.CreateBounded<BTPFrame>(5);

        private Channel<byte[]> ReceivedDataChannel = Channel.CreateBounded<byte[]>(5);

        public BTPConnection(BluetoothLEDevice device)
        {
            _device = device;
            _device.ConnectionStatusChanged += _device_ConnectionStatusChanged;
            _acknowledgementTimer = new Timer(SendStandaloneAcknowledgement, null, 2000, 5000);
        }

        public async Task ListenForResponses()
        {
            try
            {
                var segments = new List<BTPFrame>();

                while (true)
                {
                    BTPFrame btnFrame = await _incomingFrameChannel.Reader.ReadAsync();
                    Console.WriteLine("Frame Received: " + btnFrame);

                    var isBeginning = (btnFrame.ControlFlags & BTPControlFlags.Beginning) != 0;
                    var isContinuing = (btnFrame.ControlFlags & BTPControlFlags.Continuing) != 0;
                    var isEnding = (btnFrame.ControlFlags & BTPControlFlags.Ending) != 0;

                    Console.WriteLine("Beginning: {0}, Continuining: {1}, Ending: {2}", isBeginning ? "1" : "0", isContinuing ? "1" : "0", isEnding ? "1" : "0");

                    segments.Add(btnFrame);

                    // We have received the end of a sequence of messages.
                    // TODO We need to take all the Payloads and stick them together.
                    //
                    if (isEnding)
                    {
                        await ReceivedDataChannel.Writer.WriteAsync(btnFrame.Payload);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        private void _device_ConnectionStatusChanged(BluetoothLEDevice sender, object args)
        {
            // Update out internal flag in the event the other side disconnects.
            //
            Console.WriteLine("Device ConnectionStatus Changed: {0}", sender.ConnectionStatus);

            if (_isConnected)
            {
                if (sender.ConnectionStatus == BluetoothConnectionStatus.Disconnected)
                {
                    _isConnected = false;
                }
            }
        }

        private async void SendStandaloneAcknowledgement(object? state)
        {
            if (!_isConnected)
            {
                return;
            }

            await _writeCharacteristicLock.WaitAsync();

            try
            {
                Console.WriteLine($"Sending Standalone Acknowledgement for {_receivedSequenceCount}");

                BTPFrame acknowledgementFrame = new BTPFrame();
                acknowledgementFrame.Sequence = (byte)_sentSequenceNumber++;
                acknowledgementFrame.ControlFlags = BTPControlFlags.Acknowledge;

                if (_acknowledgedSequenceCount != _receivedSequenceCount)
                {
                    _acknowledgedSequenceCount = _receivedSequenceCount;
                    acknowledgementFrame.AcknowledgeNumber = (byte)_acknowledgedSequenceCount;
                }

                var writer = new MatterMessageWriter();
                acknowledgementFrame.Serialize(writer);

                await _writeCharacteristic.WriteValueWithResultAsync(writer.GetBytes().AsBuffer());
            }
            finally
            {
                _writeCharacteristicLock.Release();
            }
        }

        public async Task CloseSession()
        {
            try
            {
                await _readCharacteristic.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.None);
            }
            catch
            {
                /* Ignore */
            }
        }

        public async Task<bool> InitiateAsync()
        {
            GattDeviceServicesResult gattDeviceServicesResult = await _device.GetGattServicesAsync();

            // The GUID here is the 128 bit version of the 16 bit version (0xFFF6)
            //
            GattDeviceService gattDeviceService = _device.GetGattService(Guid.Parse("0000FFF6-0000-1000-8000-00805F9B34FB"));

            GattCharacteristicsResult gattCharacteristicsResult = await gattDeviceService.GetCharacteristicsAsync();

            foreach (var gattCharacteristic in gattCharacteristicsResult.Characteristics)
            {
                Console.WriteLine("Found characteristic {0}", gattCharacteristic.Uuid);
            }

            _writeCharacteristic = gattCharacteristicsResult.Characteristics[0];
            _readCharacteristic = gattCharacteristicsResult.Characteristics[1];

            var handshakePayload = new byte[9];
            handshakePayload[0] = 0x65; // Handshake flag set.
            handshakePayload[1] = 0x6C;
            handshakePayload[2] = 0x04;
            handshakePayload[3] = 0x00;
            handshakePayload[4] = 0x00;
            handshakePayload[3] = 0x00;
            handshakePayload[6] = 0x00;
            handshakePayload[7] = 0x00;
            handshakePayload[8] = 0x02;// Only accept two packets at a time!

            IBuffer writer = handshakePayload.AsBuffer();

            var writeResult = await _writeCharacteristic.WriteValueWithResultAsync(writer);

            // As soon as we're done writing, listen for changes from the read characteristic!
            // I don't know why it must be done in this order, but it must.
            //
            _readCharacteristic.ValueChanged += ReadCharacteristic_ValueChanged;

            await _readCharacteristic.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Indicate);

            var handshakeResponseFrame = await _incomingFrameChannel.Reader.ReadAsync();

            Console.WriteLine("------------------------------------------");
            Console.WriteLine("HandShake Response Received!");
            Console.WriteLine("Control Flags: {0:X}", handshakeResponseFrame.ControlFlags);
            Console.WriteLine("Version: {0}", handshakeResponseFrame.Version);
            Console.WriteLine("ATT High Byte: {0}", handshakeResponseFrame.ATTSize);
            Console.WriteLine("Window Size: {0}", handshakeResponseFrame.WindowSize);
            Console.WriteLine("------------------------------------------");

            _currentAttSize = handshakeResponseFrame.ATTSize;

            // If we have matching versions from the handshake, we're good to go!
            //
            _isConnected = handshakeResponseFrame.Version == 0x04;

            if (_isConnected)
            {
                await Task.Factory.StartNew(ListenForResponses);
            }

            return _isConnected;
        }

        private async void ReadCharacteristic_ValueChanged(GattCharacteristic sender, GattValueChangedEventArgs args)
        {
            Console.WriteLine("------------------------------------------");
            Console.WriteLine("Characteristic Indicated");

            var readData = new byte[args.CharacteristicValue.Length];

            using (var reader = DataReader.FromBuffer(args.CharacteristicValue))
            {
                reader.ReadBytes(readData);
            }

            Console.WriteLine(string.Join(" ", readData.Select(x => x.ToString("X2"))));

            // Check the ControlFlags.
            //
            var isHandshake = (readData[0] & 0x20) != 0;
            var isManagement = (readData[0] & 0x10) != 0;
            var isAcknowledgement = (readData[0] & 0x8) != 0;
            var isEndingSegment = (readData[0] & 0x4) != 0;
            var isContinuingSegment = (readData[0] & 0x2) != 0;
            var isBeginningSegment = (readData[0] & 0x1) != 0;

            int byteIndex = 1;

            if (isManagement)
            {
                Console.WriteLine("Management OpCode {0}", Convert.ToString(readData[byteIndex++], 2).PadLeft(8, '0'));
            }

            // The device is acknowledging a packet we send.
            //
            if (isAcknowledgement)
            {
                Console.WriteLine("Acknowledged Number {0}", readData[byteIndex++]);
            }

            Console.WriteLine("Beginning: {0}, Continuining: {1}, Ending: {2}", isBeginningSegment ? "1" : "0", isContinuingSegment ? "1" : "0", isBeginningSegment ? "1" : "0");

            if (isHandshake)
            {
                _receivedSequenceCount = 0;
            }
            else
            {
                var sequenceNumber = readData[byteIndex++];
                Console.WriteLine("Sequence Number {0}", sequenceNumber);

                _receivedSequenceCount = sequenceNumber;
            }

            // Write this frame to the channel.
            //
            var frame = new BTPFrame(readData);
            await _incomingFrameChannel.Writer.WriteAsync(frame);

            Console.WriteLine("------------------------------------------");
        }

        public async Task<byte[]> ReadAsync()
        {
            return await ReceivedDataChannel.Reader.ReadAsync();
        }

        public async Task SendAsync(byte[] bytes)
        {
            Console.WriteLine("Sending message over BTP Session");

            //var writer = new MatterMessageWriter();

            //messageFrame.Serialize(writer);

            //var message = writer.GetBytes();

            Console.WriteLine("MessageFrame is {0} bytes in length", bytes.Length);

            //Console.WriteLine(string.Join(" ", message.Select(x => x.ToString("X2"))));

            BTPFrame[] segments = GetSegments(bytes);

            Console.WriteLine("Incoming MessageFrame has been split to {0} BTPFrame segments", segments.Length);

            await _writeCharacteristicLock.WaitAsync();

            try
            {
                foreach (var btpFrame in segments)
                {
                    btpFrame.Sequence = (byte)_sentSequenceNumber++;

                    Console.WriteLine("Sending BTPFrame segment [{0}] [{1}]...", btpFrame.Sequence, Convert.ToString((byte)btpFrame.ControlFlags, 2).PadLeft(8, '0'));

                    var btpWriter = new MatterMessageWriter();

                    btpFrame.Serialize(btpWriter);

                    var writeResult = await _writeCharacteristic.WriteValueWithResultAsync(btpWriter.GetBytes().AsBuffer());

                    Console.WriteLine("Sent!");
                }

                Console.WriteLine("All segments successfully sent!");
            }
            finally
            {
                _writeCharacteristicLock.Release();
            }
        }

        private BTPFrame[] GetSegments(byte[] messageBytes)
        {
            // We might need multiple frames to transport this message.
            //
            var segments = new List<BTPFrame>();
            var messageBytesAddedToSegments = 0;

            do
            {
                BTPFrame segment = new BTPFrame();

                // If we have not created the first segment, this one will
                // have the Beginning control flag. It will also include the MessageLength.
                //
                // If we already have segments, set Continuing flag
                //
                // Depending on the type of message, we have different header lengths. E.g. for Beginning
                // we must inlude the MessageLength in the payload. For Continuing, we don't!
                // We start with the ControlFlags and the sequence number.
                //
                var headerLength = 2;

                if (segments.Count == 0)
                {
                    segment.ControlFlags = BTPControlFlags.Beginning;
                    segment.MessageLength = (ushort)messageBytes.Length;
                    headerLength += 2; // Add two bytes to the header length to indicate we have the MessageLength.

                    // If we have any outstanding messages to acknowledges, add it here!
                    //
                    if (_acknowledgedSequenceCount != _receivedSequenceCount)
                    {
                        _acknowledgedSequenceCount = _receivedSequenceCount;
                        segment.AcknowledgeNumber = (byte)_acknowledgedSequenceCount;
                        segment.ControlFlags |= BTPControlFlags.Acknowledge;

                        headerLength += 1;
                    }
                }
                else
                {
                    segment.ControlFlags = BTPControlFlags.Continuing;
                }

                // Work out how much of the messageBytes we're putting into the slice.
                //
                var howManyBytesLeftToSend = messageBytes.Length - messageBytesAddedToSegments;
                var howMuchSpaceAvailableInBTPFrame = _currentAttSize - headerLength;

                ushort segmentSize = (ushort)Math.Min(howManyBytesLeftToSend, howMuchSpaceAvailableInBTPFrame);

                var segmentBytes = new byte[segmentSize];

                // Copy from our messageBytes into segmentBytes
                //
                System.Buffer.BlockCopy(messageBytes, messageBytesAddedToSegments, segmentBytes, 0, segmentBytes.Length);

                // If the current segmentSize + all the bytes already added equals the total,
                // we send the Ending flag.
                //
                if (segmentSize + messageBytesAddedToSegments == messageBytes.Length)
                {
                    segment.ControlFlags |= BTPControlFlags.Ending;
                }

                segment.Payload = segmentBytes;

                segments.Add(segment);

                messageBytesAddedToSegments += segmentSize;

            }
            while (messageBytesAddedToSegments < messageBytes.Length);

            return segments.ToArray();
        }
    }
}
