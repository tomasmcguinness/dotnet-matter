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
        private byte _currentSequenceNumber = 0;

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

            var writeResult = await _writeCharacteristic.WriteValueAsync(writer);

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
            //Console.WriteLine("Message Length {0}", BitConverter.ToUInt16(readData, 4));

            _btpResponse = [.. readData];

            _responseReceivedSemaphore.Release();
        }

        internal async Task<byte[]> SendAsync(byte[] message)
        {
            Console.WriteLine("Sending message over BTP Session");

            // We need to check the size of this message array and break it up into 
            // multiple BTPFrames.
            //
            if (message.Length > _currentAttSize)
            {
                Console.WriteLine("Message being sent over BTP is larger than ATT Size");
            }

            var btpPayload = new byte[6 + message.Length];
            btpPayload[0] = 0x20; // Management flag set.
            btpPayload[1] = 0x6C;
            btpPayload[2] = 0x04;
            btpPayload[3] = 0x00;
            btpPayload[4] = (byte)message.Length;

            IBuffer writer = message.AsBuffer();
            var writeResult = await _writeCharacteristic.WriteValueAsync(writer);

            _currentSequenceNumber++;

            var response = await WaitForResponseToCommandAsync();

            return response;
        }
    }
}
