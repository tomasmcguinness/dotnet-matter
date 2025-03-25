using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace Matter.Core.BTP
{
    class BTPSession
    {
        private SemaphoreSlim _responseReceivedSemaphore = new SemaphoreSlim(0);
        private BluetoothLEDevice _device;
        private GattCharacteristic _readCharacteristic;
        private GattCharacteristic _writeCharacteristic;
        private ushort _currentAttSize;

        public BTPSession(BluetoothLEDevice device)
        {
            _device = device;
        }

        public async Task<bool> InitiateAsync()
        {
            GattDeviceServicesResult gattDeviceServicesResult = await _device.GetGattServicesAsync();

            GattDeviceService gattDeviceService = _device.GetGattService(Guid.Parse("0000FFF6-0000-1000-8000-00805F9B34FB"));

            GattCharacteristicsResult gattCharacteristicsResult = await gattDeviceService.GetCharacteristicsAsync();

            foreach (var gattCharacteristic in gattCharacteristicsResult.Characteristics)
            {
                Console.WriteLine("Found characteristic {0}", gattCharacteristic.Uuid);
            }

            _writeCharacteristic = gattCharacteristicsResult.Characteristics[0];
            _readCharacteristic = gattCharacteristicsResult.Characteristics[1];

            var handshakePayload = new byte[9];
            handshakePayload[0] = 0x65;
            handshakePayload[1] = 0x6C;
            handshakePayload[2] = 0x04;
            handshakePayload[3] = 0x00;
            handshakePayload[4] = 0x00;
            handshakePayload[3] = 0x00;
            handshakePayload[6] = 0x00;
            handshakePayload[6] = 0x00;
            handshakePayload[6] = 244;

            IBuffer writer = handshakePayload.AsBuffer();

            var writeResult = await _writeCharacteristic.WriteValueWithResultAsync(writer);

            // As soon as we're done writing, listen for changes from the read characteristic!
            // I don't know why it must be done in this order, but it must.
            //
            _readCharacteristic.ValueChanged += ReadCharacteristic_ValueChanged;

            await _readCharacteristic.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Indicate);

            var response = await WaitForResponseToCommandAsync();

            Console.WriteLine("HandShake Response Received!");
            Console.WriteLine("------------------------------------------");
            Console.WriteLine("Control Flags: {0:X}", response[0]);
            Console.WriteLine("Management Opcode: {0:X}", response[1]);
            Console.WriteLine("Version: {0}", response[2]);
            Console.WriteLine("ATT Low Byte: {0}", response[3]);
            Console.WriteLine("ATT High Byte: {0}", response[4]);
            Console.WriteLine("Window Size: {0}", response[5]);
            Console.WriteLine("------------------------------------------");

            _currentAttSize = BitConverter.ToUInt16(response, 3);

            // If we have matching versions from the handshake, we're good to go!
            //
            return response[2] == 0x04;
        }

        private async Task<byte[]> WaitForResponseToCommandAsync()
        {
            await _responseReceivedSemaphore.WaitAsync();

            return _btpResponse;
        }

        private byte[] _btpResponse;

        private void ReadCharacteristic_ValueChanged(GattCharacteristic sender, GattValueChangedEventArgs args)
        {
            Console.WriteLine("Characteristic Indicated");

            var readData = new byte[args.CharacteristicValue.Length];

            using (var reader = DataReader.FromBuffer(args.CharacteristicValue))
            {
                reader.ReadBytes(readData);
            }

            // If it's not a handshake result, log the contents.
            //
            // Print some of the common stuff.
            //
            Console.WriteLine("Control Flags {0}", Convert.ToString(readData[0], 2).PadLeft(8, '0'));

            // Check the ControlFlags.
            //
            var isHandshake = (readData[0] & 0x1000000) != 0;
            var isManagement = (readData[0] & 0x100000) != 0;
            var isAcknowledgement = (readData[0] & 0x1000) != 0;
            var isEndingSegment = (readData[0] & 0x100) != 0;
            var isContinuingSegment = (readData[0] & 0x10) != 0;
            var isBeginningSegment = (readData[0] & 0x1) != 0;

            int byteIndex = 1;

            if (isManagement)
            {
                Console.WriteLine("Management OpCode {0}", Convert.ToString(readData[byteIndex++], 2).PadLeft(8, '0'));
            }

            if (isAcknowledgement)
            {
                Console.WriteLine("Ack Number {0}", readData[byteIndex++]);
            }

            Console.WriteLine("Sequence Number {0}", readData[byteIndex++]);

            _btpResponse = [.. readData];

            _responseReceivedSemaphore.Release();
        }

        internal async Task<byte[]> SendAsync(MessageFrame messageFrame)
        {
            Console.WriteLine("Sending message over BTP Session");

            var writer = new MatterMessageWriter();

            messageFrame.Serialize(writer);

            var message = writer.GetBytes();

            BTPFrame[] segments = GetSegments(message);

            foreach (var btpFrame in segments)
            {
                Console.WriteLine("Sending BTPFrame segment...");

                var btpWriter = new MatterMessageWriter();

                btpFrame.Serialize(btpWriter);

                var writeResult = await _writeCharacteristic.WriteValueWithResultAsync(btpWriter.GetBytes().AsBuffer());
                var response = await WaitForResponseToCommandAsync();

                // Do something with the response?? 
                // We might need to stitch the response messages back together???
                //
            }

            return new byte[0];
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
                // 
                var headerLength = 0;

                if (segments.Count == 0)
                {
                    segment.ControlFlags = BTPControlFlags.Beginning;
                    headerLength += 1;
                    segment.MessageLength = (ushort)messageBytes.Length;
                    headerLength += 2;
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
            }
            while (messageBytesAddedToSegments < messageBytes.Length);

            return segments.ToArray();
        }
    }
}
