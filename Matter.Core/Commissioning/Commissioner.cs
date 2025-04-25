using Matter.Core.BTP;
using Matter.Core.Cryptography;
using Matter.Core.Discovery;
using Matter.Core.Sessions;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;
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
            StartNetworkDiscovery().Wait();

            //StartBluetoothDiscovery();
        }

        private async Task StartNetworkDiscovery()
        {
            var discoverer = new DnsDiscoverer();
            await discoverer.DiscoverCommissionableNodes();
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

        private BTPConnection _btpSession;
        private int _matterMessageCounter = 0;

        private async void BluetoothLEAdvertisementWatcher_Received(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            // If we got this advertisment already, just ignore it.
            //
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
                        // Stop listening for advertisments.
                        //
                        sender.Stop();

                        Console.WriteLine("Matter device discovered with the specified discriminator of {0}", disriminator);

                        // Initial a handshake!
                        //
                        var device = await BluetoothLEDevice.FromBluetoothAddressAsync(args.BluetoothAddress);

                        Console.WriteLine("Matter device has named {0}", device.Name);
                        Console.WriteLine("Starting BTPSession");

                        _btpSession = new BTPConnection(device);

                        var isConnected = await _btpSession.InitiateAsync();

                        if (isConnected)
                        {
                            Console.WriteLine("BTPSession has been established. Starting PASE Exchange....");

                            // We start with an Unsecured Session.
                            //
                            var unsecureSession = new UnsecureSession(_btpSession);

                            var unsecureExchange = unsecureSession.CreateExchange();

                            // Perform the PASE exchange.
                            //
                            var PBKDFParamRequest = new MatterTLV();
                            PBKDFParamRequest.AddStructure();

                            // We need a control octet, the tag, the length and the value.
                            //
                            var initiatorRandomBytes = RandomNumberGenerator.GetBytes(32);
                            PBKDFParamRequest.Add4OctetString(1, initiatorRandomBytes);
                            PBKDFParamRequest.AddUInt16(2, (ushort)Random.Shared.Next(1, ushort.MaxValue));
                            PBKDFParamRequest.AddUInt16(3, 0);
                            PBKDFParamRequest.AddBool(4, false);
                            PBKDFParamRequest.EndContainer();

                            // Construct a payload to carry this TLV message.
                            //
                            var messagePayload = new MessagePayload(PBKDFParamRequest);

                            messagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                            // Table 14. Protocol IDs for the Matter Standard Vendor ID
                            messagePayload.ProtocolId = 0x00;
                            // From Table 18. Secure Channel Protocol Opcodes
                            messagePayload.ProtocolOpCode = 0x20; // PBKDFParamRequest

                            var messageFrame = new MessageFrame(messagePayload);

                            // The Message Header
                            // The Session ID field SHALL be set to 0.
                            // The Session Type bits of the Security Flags SHALL be set to 0.
                            // In the PASE messages from the initiator, S Flag SHALL be set to 1 and DSIZ SHALL be set to 0.
                            //
                            // Message Flags (1byte) 0000100 0x04
                            // SessionId (2bytes) 0x00
                            // SecurityFlags (1byte) 0x00
                            //
                            messageFrame.MessageFlags |= MessageFlags.S;
                            messageFrame.SessionID = 0x00;
                            messageFrame.SecurityFlags = 0x00;

                            // Generate a random SourceNodeId
                            //
                            Random random = new Random();
                            long sourceNodeId = random.NextInt64(1, long.MaxValue);
                            messageFrame.SourceNodeID = (ulong)sourceNodeId;

                            await unsecureExchange.SendAsync(messageFrame);
                            var responseMessageFrame = await unsecureExchange.ReceiveAsync();

                            Console.WriteLine("Message received");
                            Console.WriteLine("MessageFlags: {0:X2}\nSessionId: {1:X2}\nSecurityFlags: {2:X2}\nMessageCounter: {3:X2}\nExchangeFlags: {4:X2}\nProtocol OpCode: {5:X2}\nExchange Id: {6:X2}\nProtocolId: {7:X2}",
                                (byte)responseMessageFrame.MessageFlags,
                                responseMessageFrame.SessionID,
                                (byte)responseMessageFrame.SecurityFlags,
                                responseMessageFrame.MessageCounter,
                                (byte)responseMessageFrame.MessagePayload.ExchangeFlags,
                                responseMessageFrame.MessagePayload.ProtocolOpCode,
                                responseMessageFrame.MessagePayload.ExchangeID,
                                responseMessageFrame.MessagePayload.ProtocolId
                            );

                            // We have to walk the response.
                            //
                            var PBKDFParamResponse = responseMessageFrame.MessagePayload.Payload;

                            PBKDFParamResponse.OpenStructure();

                            var initiatorRandomBytes2 = PBKDFParamResponse.GetOctetString(1);
                            var responderRandomBytes = PBKDFParamResponse.GetOctetString(2);
                            var responderSessionId = PBKDFParamResponse.GetUnsignedShort(3);

                            PBKDFParamResponse.OpenStructure(4);

                            var iterations = PBKDFParamResponse.GetUnsignedShort(1);
                            var salt = PBKDFParamResponse.GetOctetString(2);

                            Console.WriteLine("Iterations: {0}\nSalt: {1}\nSalt Base64: {2}", iterations, Encoding.ASCII.GetString(salt), Convert.ToBase64String(salt));

                            PBKDFParamResponse.CloseStructure();

                            // TODO Read tag 5

                            // TODO Ensure the last byte is now an EndContainer; 
                            //payload.CloseStructure();

                            // Create PAKE1
                            //

                            // We first need to generate a context for the SPAKE exchange.
                            // hash([SPAKE_CONTEXT, requestPayload, responsePayload])
                            //
                            // From 3.10.3. Computation of transcript TT
                            //
                            var SPAKE_CONTEXT = Encoding.ASCII.GetBytes("CHIP PAKE V1 Commissioning");

                            var contextToHash = new List<byte>();

                            contextToHash.AddRange(SPAKE_CONTEXT);
                            contextToHash.AddRange(PBKDFParamRequest.GetBytes());
                            contextToHash.AddRange(PBKDFParamResponse.GetBytes());

                            var sessionContextHash = SHA256.HashData(contextToHash.ToArray());

                            Console.WriteLine(string.Join(",", sessionContextHash));
                            Console.WriteLine("Context: {0}", BitConverter.ToString(SPAKE_CONTEXT));
                            Console.WriteLine("Request: {0}", BitConverter.ToString(PBKDFParamRequest.GetBytes()));
                            Console.WriteLine("Response: {0}", BitConverter.ToString(PBKDFParamResponse.GetBytes()));
                            Console.WriteLine("Hash: {0}", BitConverter.ToString(sessionContextHash));

                            // Build the PAKE1 message
                            //
                            var pake1 = new MatterTLV();
                            pake1.AddStructure();

                            var (w0, w1, x, X) = CryptographyMethods.Crypto_PAKEValues_Initiator(20202021, iterations, salt);

                            var byteString = X.GetEncoded(false).ToArray();

                            //Console.WriteLine("Iterations: {0}\nSalt: {1}\nSalt Base64: {2}\npA: {3}", iterations, Encoding.ASCII.GetString(salt), Convert.ToBase64String(salt), Convert.ToBase64String(byteString));

                            Console.WriteLine("X: {0}", BitConverter.ToString(byteString));

                            pake1.Add1OctetString(1, byteString);

                            pake1.EndContainer();

                            var pake1MessagePayload = new MessagePayload(pake1);

                            pake1MessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                            // Table 14. Protocol IDs for the Matter Standard Vendor ID
                            pake1MessagePayload.ProtocolId = 0x00;
                            // From Table 18. Secure Channel Protocol Opcodes
                            pake1MessagePayload.ProtocolOpCode = 0x22; //PASE Pake1

                            var pake1MessageFrame = new MessageFrame(pake1MessagePayload);

                            // The Message Header
                            // The Session ID field SHALL be set to 0.
                            // The Session Type bits of the Security Flags SHALL be set to 0.
                            // In the PASE messages from the initiator, S Flag SHALL be set to 1 and DSIZ SHALL be set to 0.
                            //
                            // Message Flags (1byte) 0000100 0x04
                            // SessionId (2bytes) 0x00
                            // SecurityFlags (1byte) 0x00
                            //
                            pake1MessageFrame.MessageFlags |= MessageFlags.S;
                            pake1MessageFrame.SessionID = 0x00;
                            pake1MessageFrame.SecurityFlags = 0x00;

                            // Generate a random SourceNodeId
                            //
                            pake1MessageFrame.SourceNodeID = (ulong)sourceNodeId;

                            await unsecureExchange.SendAsync(pake1MessageFrame);

                            var pake2MessageFrame = await unsecureExchange.ReceiveAsync();

                            Console.WriteLine("Message received");
                            Console.WriteLine("MessageFlags: {0:X2}\nSessionId: {1:X2}\nSecurityFlags: {2:X2}\nMessageCounter: {3:X2}\nExchangeFlags: {4:X2}\nProtocol OpCode: {5:X2}\nExchange Id: {6:X2}\nProtocolId: {7:X2}",
                                (byte)pake2MessageFrame.MessageFlags,
                                pake2MessageFrame.SessionID,
                                (byte)pake2MessageFrame.SecurityFlags,
                                pake2MessageFrame.MessageCounter,
                                (byte)pake2MessageFrame.MessagePayload.ExchangeFlags,
                                pake2MessageFrame.MessagePayload.ProtocolOpCode,
                                pake2MessageFrame.MessagePayload.ExchangeID,
                                pake2MessageFrame.MessagePayload.ProtocolId
                            );

                            var pake2 = pake2MessageFrame.MessagePayload.Payload;

                            pake2.OpenStructure();

                            var Y = pake2.GetOctetString(1);
                            var Verifier = pake2.GetOctetString(2);

                            Console.WriteLine("Y: {0}", BitConverter.ToString(Y).Replace("-", ""));
                            Console.WriteLine("Verifier: {0}", BitConverter.ToString(Verifier).Replace("-", ""));

                            pake2.CloseStructure();

                            // Compute Pake3
                            //
                            var (Ke, hAY, hBX) = CryptographyMethods.Crypto_P2(sessionContextHash, w0, w1, x, X, Y);

                            if (!hBX.SequenceEqual(Verifier))
                            {
                                throw new Exception("Verifier doesn't match!");
                            }

                            var pake3 = new MatterTLV();
                            pake3.AddStructure();

                            pake3.Add1OctetString(1, hAY);

                            pake3.EndContainer();

                            var pake3MessagePayload = new MessagePayload(pake3);

                            pake3MessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                            // Table 14. Protocol IDs for the Matter Standard Vendor ID
                            pake3MessagePayload.ProtocolId = 0x00;
                            // From Table 18. Secure Channel Protocol Opcodes
                            pake3MessagePayload.ProtocolOpCode = 0x24; //PASE Pake3

                            var pake3MessageFrame = new MessageFrame(pake3MessagePayload);

                            // The Message Header
                            // The Session ID field SHALL be set to 0.
                            // The Session Type bits of the Security Flags SHALL be set to 0.
                            // In the PASE messages from the initiator, S Flag SHALL be set to 1 and DSIZ SHALL be set to 0.
                            //
                            // Message Flags (1byte) 0000100 0x04
                            // SessionId (2bytes) 0x00
                            // SecurityFlags (1byte) 0x00
                            //
                            pake3MessageFrame.MessageFlags |= MessageFlags.S;
                            pake3MessageFrame.SessionID = 0x00;
                            pake3MessageFrame.SecurityFlags = 0x00;

                            // Generate a random SourceNodeId
                            //
                            pake3MessageFrame.SourceNodeID = (ulong)sourceNodeId;

                            await unsecureExchange.SendAsync(pake3MessageFrame);

                            var pakeFinishedMessageFrame = await unsecureExchange.ReceiveAsync();

                            // We now have enough to establish a secure connection
                            //
                            // We keep the same Bluetooth Connection and continue using the BTP, but this time we will be encrypting the data.
                            //
                            // Ke is our shared secret.
                            //
                            byte[] info = Encoding.ASCII.GetBytes("SessionKeys");

                            var emptySalt = new byte[0];

                            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
                            hkdf.Init(new HkdfParameters(Ke, emptySalt, info));

                            var keys = new byte[48];
                            hkdf.GenerateBytes(keys, 0, 48);

                            Console.WriteLine("KcAB: {0}", BitConverter.ToString(keys));

                            var decryptKey = keys.AsSpan().Slice(0, 16).ToArray();
                            var encryptKey = keys.AsSpan().Slice(16, 16).ToArray();
                            var attestationKey = keys.AsSpan().Slice(32, 16).ToArray();

                            Console.WriteLine("decryptKey: {0}", BitConverter.ToString(decryptKey));
                            Console.WriteLine("encryptKey: {0}", BitConverter.ToString(encryptKey));
                            Console.WriteLine("attestationKey: {0}", BitConverter.ToString(attestationKey));

                            // TODO Pass in the keys
                            //
                            var secureSession = new PaseSecureSession(_btpSession, encryptKey);

                            // We need to create a new Exchange, one that's secure.
                            //
                            var secureExchange = secureSession.CreateExchange();

                            var readCluster = new MatterTLV();
                            readCluster.AddStructure();

                            readCluster.AddArray(tagNumber: 0);
                            readCluster.EndContainer();

                            readCluster.AddArray(tagNumber: 1);
                            readCluster.EndContainer();

                            readCluster.AddArray(tagNumber: 2);
                            readCluster.EndContainer();

                            readCluster.AddBool(tagNumber: 3, false);

                            // Add the InteractionModelRevision number.
                            //
                            readCluster.AddUInt8(255, 12);

                            readCluster.EndContainer();

                            var readClusterMessagePayload = new MessagePayload(readCluster);

                            readClusterMessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                            // Table 14. Protocol IDs for the Matter Standard Vendor ID
                            readClusterMessagePayload.ProtocolId = 0x01; // IM Protocol Messages
                            // From Table 18. Secure Channel Protocol Opcodes
                            readClusterMessagePayload.ProtocolOpCode = 0x2; // ReadRequest

                            var readClusterMessageFrame = new MessageFrame(readClusterMessagePayload);

                            //A Secure Unicast Session SHALL be indicated when Session Type is Unicast Session and Session ID is NOT 0.
                            //
                            readClusterMessageFrame.MessageFlags |= MessageFlags.S;
                            readClusterMessageFrame.SecurityFlags = 0x00;
                            readClusterMessageFrame.SourceNodeID = (ulong)sourceNodeId;

                            //var memoryStream = new MemoryStream();
                            //var nonceWriter = new BinaryWriter(memoryStream);

                            //nonceWriter.Write((byte)readClusterMessageFrame.SecurityFlags);
                            //nonceWriter.Write(BitConverter.GetBytes(readClusterMessageFrame.MessageCounter));
                            //nonceWriter.Write(BitConverter.GetBytes(readClusterMessageFrame.SourceNodeID));
                            
                            //var nonce = memoryStream.ToArray();

                            //memoryStream = new MemoryStream();
                            //var additionalDataWriter = new BinaryWriter(memoryStream);

                            //additionalDataWriter.Write((byte)readClusterMessageFrame.SecurityFlags);
                            //additionalDataWriter.Write(BitConverter.GetBytes(readClusterMessageFrame.MessageCounter));
                            //additionalDataWriter.Write(BitConverter.GetBytes(readClusterMessageFrame.SourceNodeID));

                            //var additionalData = memoryStream.ToArray();


                            //var messageWriter = new MatterMessageWriter();
                            //readClusterMessagePayload.Serialize(messageWriter);
                            //var payload = messageWriter.GetBytes();

                            //byte[] cipherText = new byte[payload.Length];
                            //byte[] tag = new byte[16];

                            //var encryptor = new AesCcm(encryptKey);
                            //encryptor.Encrypt(nonce, payload, cipherText, tag, additionalData);

                            await secureExchange.SendAsync(readClusterMessageFrame);

                            var readClusterResponseMessageFrame = await secureExchange.ReceiveAsync();
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
            resetEvent.WaitOne(60000);
        }
    }
}
