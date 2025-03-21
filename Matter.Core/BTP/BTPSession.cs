using System.Reflection.PortableExecutable;
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

        public BTPSession(BluetoothLEDevice device)
        {
            _device = device;
        }

        public async Task InitiateAsync()
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

            Console.WriteLine("Write: {0}", writeResult.ToString());

            // As soon as we're done writing, listen for changes from the read characteristic!
            // I don't know why it must be done in this order, but it must.
            //
            _readCharacteristic.ValueChanged += ReadCharacteristic_ValueChanged;

            await _readCharacteristic.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Indicate);

            var response = await WaitForResponseToCommandAsync();

            Console.WriteLine("Response successfully received!");
        }

        private async Task<byte[]> WaitForResponseToCommandAsync()
        {
            await _responseReceivedSemaphore.WaitAsync();

            return new byte[0];
        }

        private void ReadCharacteristic_ValueChanged(GattCharacteristic sender, GattValueChangedEventArgs args)
        {
            // We're not interested in the response now.
            //
            sender.ValueChanged -= ReadCharacteristic_ValueChanged;

            Console.WriteLine("Characteristic Change Indicated");

            var readData = new byte[args.CharacteristicValue.Length];

            using (var reader = DataReader.FromBuffer(args.CharacteristicValue))
            {
                reader.ReadBytes(readData);
            }

            Console.WriteLine("Control Flags: {0:X}", readData[0]);
            Console.WriteLine("Management Opcode: {0:X}", readData[1]);
            Console.WriteLine("Version: {0}", readData[2]);

            _responseReceivedSemaphore.Release();
        }
    }
}
