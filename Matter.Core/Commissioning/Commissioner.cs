using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Enumeration;
using Windows.Storage.Streams;

namespace Matter.Core.Commissioning
{
    public class Commissioner
    {
        public void StartBluetoothDiscovery()
        {
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

                Console.WriteLine(string.Format("{0}|0x{1:X}|0x{2:X}", section.Data.Length, section.DataType, BitConverter.ToString(data)));
            }

            //0x1 0x06 0x16 0xF6-FF-00-00-0F-F1-FF-00-80-00

            Console.Write("\n");
        }

        private void OnDeviceAdded(DeviceWatcher sender, DeviceInformation args)
        {
            Console.WriteLine($"Found: {args.Name}");
        }

        public async Task CommissionNode()
        {
            string aqs = "System.Devices.Aep.ProtocolId:=\"{bb7bb05e-5972-42b5-94fc-76eaa7084d49}\""; // Bluetooth LE Protocol ID

            //DeviceInformationCollection collection = await DeviceInformation.FindAllAsync(aqs);

            //foreach (DeviceInformation device in collection)
            //{
            //    Console.WriteLine(device.Name);
            //}



            //var discoveredDevices = await Bluetooth.ScanForDevicesAsync();
            //Console.WriteLine($"found {discoveredDevices?.Count} devices");
            //var bluetoothClient = new BluetoothClient();
            //var watcher = new BluetoothLEAdvertisementWatcher();

            //SerialPort BlueToothConnection = new SerialPort();

            //BlueToothConnection.BaudRate = (9600);

            //BlueToothConnection.PortName = "COM4";

            //BlueToothConnection.Open();

            //var hasBluetooth = await Bluetooth.GetAvailabilityAsync();

            //if (!hasBluetooth)
            //{
            //    throw new Exception("No Bluetooth");
            //}
        }
    }
}
