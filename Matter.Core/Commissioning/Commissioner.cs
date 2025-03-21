using Windows.Devices.Bluetooth.Advertisement;
using Windows.Storage.Streams;

namespace Matter.Core.Commissioning
{
    public class Commissioner
    {
        public void StartBluetoothDiscovery()
        {
            // TODO Abstract the Bluetooth code behind an interface so we can use different providers
            // e.g. Linux. Using the BluetoothLEAdvertisementWatcher ties us to Windows.
            //
            BluetoothLEAdvertisementWatcher bluetoothLEAdvertisementWatcher = new();
            bluetoothLEAdvertisementWatcher.AllowExtendedAdvertisements = true;
            bluetoothLEAdvertisementWatcher.ScanningMode = BluetoothLEScanningMode.Active;
            bluetoothLEAdvertisementWatcher.Received += BluetoothLEAdvertisementWatcher_Received;
            bluetoothLEAdvertisementWatcher.Start();
        }

        private async void BluetoothLEAdvertisementWatcher_Received(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            foreach (var section in args.Advertisement.DataSections)
            {
                var data = new byte[section.Data.Length];
                using (var reader = DataReader.FromBuffer(section.Data))
                {
                    reader.ReadBytes(data);
                }

                // Check the payload. If we find 0xFFF6 we have a Matter advertising packet.
                //
                if (section.DataType == 0x16 && data[0] == 0xF6 && data[1] == 0xFF)
                {
                    // Check the discriminator (it's in bytes 3 and 4)
                    //
                    var disriminator = BitConverter.ToUInt16(data, 3);

                    Console.WriteLine("Matter device payload received from {0} [{1}] with a disriminator of {2}", args.BluetoothAddress, args.BluetoothAddressType, disriminator);
                }
            }
        }
    }
}
