using ColdBear.Climenole;
using Microsoft.UI.Xaml;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace Commissioner.App
{
    public sealed partial class MainWindow : Window
    {
        private BluetoothLEAdvertisementWatcher _watcher;
        private GattDeviceService _btpService;
        private short _currentDiscriminator;
        private int _currentSetupCode;

        private const string MATTER_BLE_SERVICE_UUID = "0000fff6-0000-1000-8000-00805f9b34fb";

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
            // If we have already received an advertisment from this device, just ignore it for now.
            //
            if (_devices.Contains(args.BluetoothAddress))
            {
                return;
            }

            _devices.Add(args.BluetoothAddress);

            foreach (var section in args.Advertisement.DataSections)
            {
                // Check the service data. This is where the discriminator will be found.
                //
                if (section.DataType == 0x16)
                {
                    DataReader dataReader = DataReader.FromBuffer(section.Data);
                    byte[] bytes = new byte[section.Data.Length];
                    dataReader.ReadBytes(bytes);

                    // Bytes 3 and 4 will be the discriminator - from the Advertising PDU payload
                    // They make up part of a 12 bit value.
                    //
                    var discriminatorBytes = new byte[2];

                    Array.Copy(bytes, 3, discriminatorBytes, 0, 2);

                    var discriminator = BitConverter.ToInt16(discriminatorBytes, 0);

                    if (discriminator == _currentDiscriminator)
                    {
                        // We have found the device we're interested in, so stop listening to advertisments.
                        //
                        _watcher.Stop();

                        var device = await BluetoothLEDevice.FromBluetoothAddressAsync(args.BluetoothAddress);

                        Debug.WriteLine($"Device Found: {device.Name}");

                        try
                        {
                            var gatt = await device.GetGattServicesAsync();

                            Debug.WriteLine($"{device.Name} Services: {gatt.Services.Count}, {gatt.Status}, {gatt.ProtocolError}");

                            foreach (var service in gatt.Services)
                            {
                                Debug.WriteLine($"Service UUID {service.Uuid}");
                            }

                            _btpService = device.GetGattService(Guid.Parse(MATTER_BLE_SERVICE_UUID));

                            var openStatus = await _btpService.OpenAsync(GattSharingMode.SharedReadAndWrite);

                            if(openStatus != GattOpenStatus.Success)
                            {
                                _btpService = null;
                                throw new InvalidOperationException();
                            }

                            // Fetch all the characteristics. We're expecting at least two.
                            //
                            var btpCharacteristics = await _btpService.GetCharacteristicsAsync();

                            BitArray handShake = new BitArray(8);
                            handShake[1] = true;
                            handShake[2] = true;
                            handShake[5] = true;
                            handShake[7] = true;

                            byte[] handShakeBytes = new byte[9];

                            handShake.CopyTo(handShakeBytes, 0);

                            handShakeBytes[1] = 0x6C;
                            handShakeBytes[2] = 0x04;

                            byte[] byteArray = BitConverter.GetBytes((short)23);
                            byteArray.CopyTo(handShakeBytes, 6);

                            handShakeBytes[8] = 5;

                            GattWriteResult writeResult;

                            writeResult = await btpCharacteristics.Characteristics[0].WriteValueWithResultAsync(handShakeBytes.AsBuffer());

                            if (writeResult.Status != GattCommunicationStatus.Success)
                            {
                                throw new InvalidOperationException();
                            }

                            btpCharacteristics.Characteristics[1].ValueChanged += MainWindow_ValueChanged;

                            await Task.Delay(1000);

                            writeResult = await btpCharacteristics.Characteristics[1].WriteClientCharacteristicConfigurationDescriptorWithResultAsync(GattClientCharacteristicConfigurationDescriptorValue.Indicate);

                            if (writeResult.Status != GattCommunicationStatus.Success)
                            {
                                throw new InvalidOperationException();
                            }

                            //bkdfparamreq -struct => STRUCTURE[tag - order]
                            //{
                            //  initiatorRandom[1] : OCTET STRING[length 32],
                            //  initiatorSessionId[2] : UNSIGNED INTEGER[range 16 - bits],
                            //  passcodeId[3] : UNSIGNED INTEGER[length 16 - bits],
                            //  hasPBKDFParameters[4] : BOOLEAN,
                            //  initiatorSEDParams[5, optional] : sed-parameter-struct
                            //}

                            //MatterTLV pbkdfRequestTLV = new();

                            //pbkdfRequestTLV.AddOctetString(RandomString(32))
                            //    .AddUnsignedTwoOctetInteger(11)
                            //    .AddUnsignedOneOctetInteger(3840)
                            //    .AddBooleanFalse();

                            // Put this payload into a Matter Payload.

                            // Put the matter payload into BTP payloads.
                            //

                            //await WriteMatterMessageViaBle(pbkdfRequestTLV, btpCharacteristics.Characteristics[0]);
                            //await btpCharacteristics.Characteristics[0].WriteValueAsync(handShakeBytes.AsBuffer());
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine(ex.ToString());
                            device.Dispose();
                        }
                    }
                }
            }
        }

        private async Task WriteMatterMessageViaBle(MatterTLV pbkdfRequestTLV, GattCharacteristic gattCharacteristic)
        {
            // We need to create the matter messages from this payload.
            //

            await WriteBtpPackets(new byte[100], gattCharacteristic);
        }

        private async Task WriteBtpPackets(byte[] bytes, GattCharacteristic gattCharacteristic)
        {
            // 244 is the maximum size we agreed.
            // Split the bytes into multiple payloads if required, using the beginning, end and sequenceNumbers.
            //
            BtpPacket packet = new(false, true, false, true, true, 0, 0, (short)bytes.Length, bytes);

            GattCommunicationStatus status;

            status = await gattCharacteristic.WriteValueAsync(packet.Bytes.AsBuffer());

            if (status != GattCommunicationStatus.Success)
            {
                throw new InvalidOperationException();
            }
        }

        private static Random random = new Random();

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private void MainWindow_ValueChanged(GattCharacteristic sender, GattValueChangedEventArgs args)
        {
            throw new NotImplementedException();
        }

        private void myButton_Click(object sender, RoutedEventArgs e)
        {
            // Parse this to manual pairing code and extract the discriminator and passcode
            // We'll need this to correctly identify and connect to the device.
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
            Debug.WriteLine($"Discriminator: {_currentDiscriminator}");

            // Start discovery looking for a device with the specified discriminator!
            //
            _devices.Clear();
            _watcher.Start();
        }
    }
}
