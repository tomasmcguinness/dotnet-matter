using Matter.Core.BTP;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Storage.Streams;

namespace Matter.Core.Commissioning
{
    public class CommissioningThread
    {
        private readonly int _discriminator;
        private readonly ManualResetEvent _resetEvent;
        private readonly List<ulong> _receivedAdvertisments = new();

        public CommissioningThread(int number, ManualResetEvent resetEvent)
        {
            _discriminator = number;
            _resetEvent = resetEvent;
        }

        public void PerformDiscovery()
        {
            StartBluetoothDiscovery();
        }

        private void StartBluetoothDiscovery()
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

        private BTPSession _btpSession;
        private int _matterMessageCounter = 0;

        private async void BluetoothLEAdvertisementWatcher_Received(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            if (_receivedAdvertisments.Contains(args.BluetoothAddress))
            {
                return;
            }

            _receivedAdvertisments.Add(args.BluetoothAddress);

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

                    Console.WriteLine("Matter device advertisment received from {0} [{1}] with a disriminator of {2}", args.BluetoothAddress, args.BluetoothAddressType, disriminator);

                    if (disriminator == _discriminator)
                    {
                        sender.Stop();

                        Console.WriteLine("Matter device discovered with the specified discriminator of {0}", disriminator);

                        // Initial a handshake!
                        //
                        var device = await BluetoothLEDevice.FromBluetoothAddressAsync(args.BluetoothAddress);

                        Console.WriteLine("Matter device has named {0}", device.Name);
                        Console.WriteLine("Starting BTPSession");

                        _btpSession = new BTPSession(device);

                        var isConnected = await _btpSession.InitiateAsync();

                        if (isConnected)
                        {
                            // Perform the PASE 
                            //
                            var PBKDFParamRequest = new MatterTLV();
                            PBKDFParamRequest.AddStructure();
                            PBKDFParamRequest.EndContainer();

                            var applicationPayload = PBKDFParamRequest.GetBytes();

                            // Let's build up the Protocol Header
                            //
                            var messagePayload = new byte[6 + applicationPayload.Length];
                            messagePayload[0] = 0x01;// Protocol Header
                            messagePayload[1] = 0x00;// Protocol OpCode
                            messagePayload[2] = 0x00;// Exchange Id
                            messagePayload[3] = 0x00;// Exchange Id
                            messagePayload[4] = 0x00;// Protocol Id
                            messagePayload[5] = 0x00;// Protocol Id

                            foreach (var b in applicationPayload)
                            {
                                messagePayload.Append(b);
                            }

                            // The Message Header
                            // The Session ID field SHALL be set to 0.
                            // The Session Type bits of the Security Flags SHALL be set to 0.
                            // In the PASE messages from the initiator, S Flag SHALL be set to 1 and DSIZ SHALL be set to 0.
                            //
                            // Message Flags (1byte) 0000100 0x04
                            // SessionId (2bytes) 0x00
                            // SecurityFlags (1byte) 0x00
                            // MessageCount (4bytes) _matterMessageCounter
                            // Message
                            // MessageFooter (not needed for unsecured messages)


                            var message = new byte[8 + messagePayload.Length];
                            message[0] = 0x04;
                            message[1] = 0x00;
                            message[2] = 0x00;
                            message[3] = 0x00;
                            message[4] = 0x00;
                            message[5] = 0x00;
                            message[6] = 0x00;
                            message[7] = 0x00;

                            foreach (var b in messagePayload)
                            {
                                message.Append(b);
                            }

                            await _btpSession.SendAsync(message);
                        }

                        _resetEvent.Set();
                    }
                }
            }
        }
    }

    public class Commissioner
    {
        public void CommissionDevice(int discriminator)
        {
            ManualResetEvent resetEvent = new ManualResetEvent(false);

            // Run the commissioning in a thread.
            //
            var commissioningThread = new CommissioningThread(discriminator, resetEvent);

            new Thread(new ThreadStart(commissioningThread.PerformDiscovery)).Start();

            // Give the thread 20 seconds to complete commissioning.
            //
            resetEvent.WaitOne(20000);
        }
    }
}
