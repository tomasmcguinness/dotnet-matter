// Copyright (c) Microsoft Corporation and Contributors.
// Licensed under the MIT License.

using Microsoft.UI.Xaml;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Media.Devices;
using Windows.Storage.Streams;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Commissioner.App
{
    /// <summary>
    /// An empty window that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainWindow : Window
    {
        private BluetoothLEAdvertisementWatcher _watcher;

        public MainWindow()
        {
            this.InitializeComponent();

            _watcher = new BluetoothLEAdvertisementWatcher();
            _watcher.Received += watcher_Received;

        }

        private List<ulong> _devices = new List<ulong>();

        private async void watcher_Received(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {

            if (_devices.Contains(args.BluetoothAddress))
            {
                return;
            }

            Debug.WriteLine("===============================");

            Debug.WriteLine(args.BluetoothAddress);
            Debug.WriteLine(args.Advertisement.LocalName);

            _devices.Add(args.BluetoothAddress);

            foreach (var section in args.Advertisement.DataSections)
            {
                // Check the service data.
                //
                if (section.DataType == 0x16)
                {
                    Debug.WriteLine("Service Data");

                    DataReader dataReader = DataReader.FromBuffer(section.Data);
                    byte[] bytes = new byte[section.Data.Length];
                    dataReader.ReadBytes(bytes);

                    string hexString = BitConverter.ToString(bytes);

                    Debug.WriteLine(section.Data.Length);

                    if (section.Data.Length == 10)
                    {
                        var device = await BluetoothLEDevice.FromBluetoothAddressAsync(args.BluetoothAddress);
                        Debug.WriteLine($"BLEWATCHER Found: {device.Name}");

                        var gatt = await device.GetGattServicesAsync();
                        Debug.WriteLine($"{device.Name} Services: {gatt.Services.Count}, {gatt.Status}, {gatt.ProtocolError}");

                        foreach (var service in gatt.Services)
                        {
                            Debug.WriteLine($"Service UUID {service.Uuid}");
                        }

                        var btpService = device.GetGattService(Guid.Parse("0000fff6-0000-1000-8000-00805f9b34fb"));

                        await btpService.OpenAsync(GattSharingMode.SharedReadAndWrite);

                        var btpCharacteristics = await btpService.GetCharacteristicsAsync();

                        foreach (var characteristic in btpCharacteristics.Characteristics)
                        {
                            Debug.WriteLine($"Characteristic UUID: {characteristic.Uuid}");
                        }
                    }

                    Debug.WriteLine(hexString);
                }
            }

            Debug.WriteLine("===============================");

            // Just build up a list of devices. The payload should contain the discriminator we need. 
            //
            //    if(args.Advertisement.ManufacturerData?.Count > 0)
            //    {
            //        foreach(var data in args.Advertisement.ManufacturerData)
            //        {
            //            if (data.CompanyId == 65535 || data.CompanyId == 89)
            //            {
            //                if (data.Data.Length >= 10)
            //                {
            //                    Debug.WriteLine(data.CompanyId);

            //                    DataReader dataReader = DataReader.FromBuffer(data.Data);
            //                    byte[] bytes = new byte[data.Data.Length];
            //                    dataReader.ReadBytes(bytes);

            //                    string hexString = BitConverter.ToString(bytes);

            //                    Debug.WriteLine(hexString);
            //                    Debug.WriteLine(hexString.Replace('-', ' '));

            //                    Debug.WriteLine("===============================");
            //                }
            //            }
            //        }
            //    }
        }

        private void myButton_Click(object sender, RoutedEventArgs e)
        {
            if (_watcher.Status == BluetoothLEAdvertisementWatcherStatus.Started)
            {
                _devices.Clear();
                _watcher.Stop();
            }
            else
            {
                _watcher.Start();
            }

            //string manualPairingCode = "34970112332";

            // Parse this to extract the setup code and discriminator
            //
        }
    }
}
