// Copyright (c) Microsoft Corporation and Contributors.
// Licensed under the MIT License.

using Microsoft.UI.Xaml;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace Commissioner.App
{
    public sealed partial class MainWindow : Window
    {
        private BluetoothLEAdvertisementWatcher _watcher;

        private short _currentDiscriminator;
        private int _currentSetupCode;

        public MainWindow()
        {
            this.InitializeComponent();

            RootGrid.DataContext = new MainWindowViewModel();

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

            _devices.Add(args.BluetoothAddress);

            foreach (var section in args.Advertisement.DataSections)
            {
                // Check the service data.
                //
                if (section.DataType == 0x16)
                {
                    DataReader dataReader = DataReader.FromBuffer(section.Data);
                    byte[] bytes = new byte[section.Data.Length];
                    dataReader.ReadBytes(bytes);

                    string hexString = BitConverter.ToString(bytes);

                    Debug.WriteLine(section.Data.Length);

                    if (section.Data.Length == 10)
                    {
                        _watcher.Stop();

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

                        BitArray handShake = new BitArray(8);
                        handShake[1] = true;
                        handShake[2] = true;
                        handShake[5] = true;
                        handShake[7] = true;

                        byte[] handShakeBytes = new byte[9];

                        handShake.CopyTo(handShakeBytes, 0);

                        handShakeBytes[1] = 0x6C;

                        //BitArray version = new BitArray(8, false);
                        //version[7] = true;

                        //version.CopyTo(handShakeBytes, 2);

                        handShakeBytes[8] = 244;

                        await btpCharacteristics.Characteristics[0].WriteValueAsync(handShakeBytes.AsBuffer());

                        btpCharacteristics.Characteristics[1].ValueChanged += MainWindow_ValueChanged;

                        GattCommunicationStatus status = await btpCharacteristics.Characteristics[1].WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Indicate);

                        if (status == GattCommunicationStatus.Success)
                        {
                            // We've done it!
                        }
                    }

                    Debug.WriteLine(hexString);
                }
            }
        }

        private void MainWindow_ValueChanged(GattCharacteristic sender, GattValueChangedEventArgs args)
        {
            throw new NotImplementedException();
        }

        private void myButton_Click(object sender, RoutedEventArgs e)
        {
            // Parse this to manual pairing code into parts
            //
            var viewModel = (MainWindowViewModel)RootGrid.DataContext;

            var digit1 = short.Parse(viewModel.ManualPairingCode.Substring(0, 1));
            var digits2to6 = int.Parse(viewModel.ManualPairingCode.Substring(1, 5));
            var digits7to10 = int.Parse(viewModel.ManualPairingCode.Substring(6, 4));

            var firstNumberBits = new BitArray(new int[] { digit1 });
            var secondNumberBits = new BitArray(new int[] { digits2to6 });
            var thirdNumberBits = new BitArray(new int[] { digits7to10 });

            var discriminatorBitArray = new BitArray(12, false);
            discriminatorBitArray[11] = firstNumberBits[0];
            discriminatorBitArray[10] = firstNumberBits[1];
            discriminatorBitArray[9] = secondNumberBits[14];
            discriminatorBitArray[8] = secondNumberBits[15];

            var discriminatorBytes = new byte[2];

            discriminatorBitArray.CopyTo(discriminatorBytes, 0);

            _currentDiscriminator = BitConverter.ToInt16(discriminatorBytes, 0);
            Debug.WriteLine($"Discriminator: {_currentDiscriminator}");

            var setupCodeBitArray = new BitArray(27);

            for (int i = 0; i < 14; i++)
            {
                setupCodeBitArray[i] = secondNumberBits[i];
            }

            for (int i = 0; i < 13; i++)
            {
                setupCodeBitArray[i + 14] = thirdNumberBits[i];
            }

            var setupCodeBytes = new byte[5];

            setupCodeBitArray.CopyTo(setupCodeBytes, 0);

            _currentSetupCode = BitConverter.ToInt32(setupCodeBytes, 0);

            Debug.WriteLine($"Setup Code: {_currentSetupCode}");

            // Start discovery looking for a device with the specified discriminator!
            //

            //if (_watcher.Status == BluetoothLEAdvertisementWatcherStatus.Started)
            //{
            //    _devices.Clear();
            //    _watcher.Stop();
            //}
            //else
            //{
            //    _watcher.Start();
            //}
        }
    }
}
