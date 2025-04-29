using Matter.Core.Cryptography;
using Matter.Core.Fabrics;
using Matter.Core.Sessions;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;

namespace Matter.Core.Commissioning
{
    public class NetworkCommissioningThread
    {
        private readonly int _discriminator;
        private readonly ManualResetEvent _resetEvent;
        private readonly List<ulong> _receivedAdvertisments = new();
        private readonly Fabric _fabric = Fabric.CreateNew("NetworkFabric");

        public NetworkCommissioningThread(int number, ManualResetEvent resetEvent)
        {
            _discriminator = number;
            _resetEvent = resetEvent;
        }

        public void PerformDiscovery(object? state)
        {
            Fabric f = state as Fabric;
            CommissionOnNetworkDevice(f).Wait();
        }

        private async Task CommissionOnNetworkDevice(Fabric fabric)
        {
            //var discoverer = new DnsDiscoverer();
            //await discoverer.DiscoverCommissionableNodes();

            try
            {
                IConnection udpConnection = new UdpConnection();

                Console.WriteLine("UDP Connection has been established. Starting PASE Exchange....");

                UnsecureSession session = new UnsecureSession(udpConnection);

                var unsecureExchange = session.CreateExchange();

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

                await unsecureExchange.SendAsync(messageFrame);

                var responseMessageFrame = await unsecureExchange.ReceiveAsync();

                Console.WriteLine("PBKDFParamResponse received");
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

                var peerSessionId = responderSessionId;

                Console.WriteLine("Responder Session Id: {0}", responderSessionId);

                PBKDFParamResponse.OpenStructure(4);

                var iterations = PBKDFParamResponse.GetUnsignedShort(1);
                var salt = PBKDFParamResponse.GetOctetString(2);

                Console.WriteLine("Iterations: {0}\nSalt Base64: {1}", iterations, Convert.ToBase64String(salt));

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

                await unsecureExchange.SendAsync(pake3MessageFrame);

                var pakeFinishedMessageFrame = await unsecureExchange.ReceiveAsync();

                Console.WriteLine("StatusReport received");

                // This is the status report.
                //
                await unsecureExchange.AcknowledgeMessageAsync(pakeFinishedMessageFrame.MessageCounter);

                // We now have enough to establish a secure connection
                //
                // We keep the same UDP Connection but this time we will be encrypting the data.
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

                var encryptKey = keys.AsSpan().Slice(0, 16).ToArray();
                var decryptKey = keys.AsSpan().Slice(16, 16).ToArray();
                var attestationKey = keys.AsSpan().Slice(32, 16).ToArray();

                Console.WriteLine("decryptKey: {0}", BitConverter.ToString(decryptKey));
                Console.WriteLine("encryptKey: {0}", BitConverter.ToString(encryptKey));
                Console.WriteLine("attestationKey: {0}", BitConverter.ToString(attestationKey));

                Console.WriteLine(format: "PeerSessionId: {0}", peerSessionId);

                // Create a PASE session
                //
                var paseSession = new PaseSecureSession(udpConnection, peerSessionId, encryptKey, decryptKey);

                // We then create a new Exchange using the secure session.
                //
                var paseExchange = paseSession.CreateExchange();

                /*
                // To test the secure session, fetch the Vendor Name using the Interaction Model.
                // ReadRequest payload.
                //
                var readCluster = new MatterTLV();
                readCluster.AddStructure();

                readCluster.AddArray(tagNumber: 0);

                readCluster.AddList();

                readCluster.AddBool(tagNumber: 0, false);
                readCluster.AddUInt64(tagNumber: 1, 0x00); // NodeId 0x00
                readCluster.AddUInt16(tagNumber: 2, 0x00); // Endpoint 0x00
                readCluster.AddUInt32(tagNumber: 3, 0x28); // ClusterId 0x28 - Basic Information
                readCluster.AddUInt32(tagNumber: 4, 0x01); // Attribute 0x01 - Vendor Name
                readCluster.AddUInt16(tagNumber: 5, 0x00); // List Index 0x00
                readCluster.AddUInt32(tagNumber: 6, 0x00); // Wildcard flags
                readCluster.EndContainer(); // Close the list

                readCluster.EndContainer(); // Close the array

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

                readClusterMessageFrame.MessageFlags |= MessageFlags.S;
                readClusterMessageFrame.SecurityFlags = 0x00;
                readClusterMessageFrame.SourceNodeID = 0x00;

                await paseExchange.SendAsync(readClusterMessageFrame);

                var readClusterResponseMessageFrame = await paseExchange.ReceiveAsync();

                */

                // Arm the failsafe. This feels very James Bond.
                //
                //var armFailsafeRequest = new MatterTLV();
                //armFailsafeRequest.AddStructure();

                //armFailsafeRequest.AddArray(tagNumber: 2);

                //armFailsafeRequest.AddList();

                //armFailsafeRequest.AddUInt16(tagNumber: 0, 0x00); // Endpoint 0x00
                //armFailsafeRequest.AddUInt32(tagNumber: 1, 0x3E); // ClusterId 0x3E - Operational Credentials
                //armFailsafeRequest.AddUInt16(tagNumber: 2, 0x04); // 11.18.6. Commands CSRRequest
                //armFailsafeRequest.EndContainer(); // Close the list

                //armFailsafeRequest.EndContainer(); // Close the array

                //armFailsafeRequest.EndContainer(); // Close the structure

                //var armFailsafeMessagePayload = new MessagePayload(armFailsafeRequest);

                //armFailsafeMessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                //// Table 14. Protocol IDs for the Matter Standard Vendor ID
                //armFailsafeMessagePayload.ProtocolId = 0x01; // IM Protocol Messages
                //armFailsafeMessagePayload.ProtocolOpCode = 0x09; // InvokeCommand

                //var armFailsafeMessageFrame = new MessageFrame(armFailsafeMessagePayload);

                //armFailsafeMessageFrame.MessageFlags |= MessageFlags.S;
                //armFailsafeMessageFrame.SecurityFlags = 0x00;
                //armFailsafeMessageFrame.SourceNodeID = 0x00;

                //await paseExchange.SendAsync(armFailsafeMessageFrame);

                //await paseExchange.ReceiveAsync();


                // Perform Step 11 of the Commissioning Flow.
                //
                var csrRequest = new MatterTLV();
                csrRequest.AddStructure();
                csrRequest.AddBool(0, false);
                csrRequest.AddBool(1, false);
                csrRequest.AddArray(tagNumber: 2); // InvokeRequests

                csrRequest.AddStructure();

                csrRequest.AddList(tagNumber: 0); // CommandPath

                csrRequest.AddUInt16(tagNumber: 0, 0x00); // Endpoint 0x00
                csrRequest.AddUInt32(tagNumber: 1, 0x3E); // ClusterId 0x3E - Operational Credentials
                csrRequest.AddUInt16(tagNumber: 2, 0x04); // 11.18.6. Commands CSRRequest

                csrRequest.EndContainer();

                csrRequest.AddStructure(1); // CommandFields

                var csrNonceBytes = RandomNumberGenerator.GetBytes(32);

                csrRequest.Add4OctetString(0, csrNonceBytes); // CSRNonce

                csrRequest.EndContainer(); // Close the CommandFields

                csrRequest.EndContainer(); // Close the structure

                csrRequest.EndContainer(); // Close the array

                csrRequest.AddUInt8(255, 12); // interactionModelRevision

                csrRequest.EndContainer(); // Close the structure

                var csrRequestMessagePayload = new MessagePayload(csrRequest);

                csrRequestMessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                // Table 14. Protocol IDs for the Matter Standard Vendor ID
                csrRequestMessagePayload.ProtocolId = 0x01; // IM Protocol Messages
                csrRequestMessagePayload.ProtocolOpCode = 0x08; // InvokeRequest

                var csrRequestMessageFrame = new MessageFrame(csrRequestMessagePayload);

                csrRequestMessageFrame.MessageFlags |= MessageFlags.S;
                csrRequestMessageFrame.SecurityFlags = 0x00;
                csrRequestMessageFrame.SourceNodeID = 0x00;

                await paseExchange.SendAsync(csrRequestMessageFrame);

                var csrResponseMessageFrame = await paseExchange.ReceiveAsync();

                Console.WriteLine(csrResponseMessageFrame.MessagePayload.Payload.ToString());

                await paseExchange.AcknowledgeMessageAsync(csrResponseMessageFrame.MessageCounter);



                /*
                 
                // Create a new Exchange as we're now exchanging SecureChannel protocol messages
                //
                paseExchange = paseSession.CreateExchange();

                // Exchange CASE Messages, starting with Sigma1
                //
                var spake1InitiatorRandomBytes = RandomNumberGenerator.GetBytes(32);
                var spake1SessionId = RandomNumberGenerator.GetBytes(16);
                var keyPair = CertificateAuthority.GenerateKeyPair();
                var fabricId = new BigInteger("123");
                var nodeId = (long)66;

                var publicKey = keyPair.Public as ECPublicKeyParameters;
                var publicKeyBytes = publicKey.Q.GetEncoded(false).ToArray();

                // Destination identifier is a composite
                //
                MemoryStream ms = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(ms);
                writer.Write(spake1InitiatorRandomBytes);
                writer.Write(spake1SessionId);
                writer.Write(fabricId.ToByteArray());
                writer.Write(nodeId);

                var destinationId = ms.ToArray();

                var hmac = new HMACSHA256(_fabric.IPK);
                byte[] hashedDestinationId = hmac.ComputeHash(destinationId);

                var sigma1Payload = new MatterTLV();
                sigma1Payload.AddStructure();

                sigma1Payload.Add4OctetString(1, spake1InitiatorRandomBytes); // initiatorRandom
                sigma1Payload.AddUInt16(2, BitConverter.ToUInt16(spake1SessionId)); // initiatorSessionId 
                sigma1Payload.Add2OctetString(3, hashedDestinationId); // destinationId
                sigma1Payload.Add2OctetString(4, publicKeyBytes); // initiatorEphPubKey

                sigma1Payload.EndContainer();

                var sigma1MessagePayload = new MessagePayload(sigma1Payload);

                sigma1MessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                // Table 14. Protocol IDs for the Matter Standard Vendor ID
                sigma1MessagePayload.ProtocolId = 0x00;
                // From Table 18. Secure Channel Protocol Opcodes
                sigma1MessagePayload.ProtocolOpCode = 0x30; // Sigma1

                var sigma1MessageFrame = new MessageFrame(sigma1MessagePayload);

                sigma1MessageFrame.MessageFlags |= MessageFlags.S;
                sigma1MessageFrame.SecurityFlags = 0x00;
                sigma1MessageFrame.SourceNodeID = 0x00;

                await paseExchange.SendAsync(sigma1MessageFrame);

                var sigma2MessageFrame = await paseExchange.ReceiveAsync();
                */

                await Task.Delay(5000);
            }
            catch (Exception exp)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error: {0}", exp.Message);
            }
        }
    }

    public class NetworkCommissioner
    {
        private readonly Fabric _fabric;

        public NetworkCommissioner()
        {
            _fabric = Fabric.CreateNew("Test");
        }

        public void CommissionDevice(int discriminator)
        {
            ManualResetEvent resetEvent = new ManualResetEvent(false);

            // Run the commissioning in a thread.
            //
            var commissioningThread = new NetworkCommissioningThread(discriminator, resetEvent);

            // Start the thread, passing the fabric as a parameter.
            //
            new Thread(new ParameterizedThreadStart(commissioningThread.PerformDiscovery)).Start(_fabric);

            // Give the thread some time to complete commissioning.
            //
            resetEvent.WaitOne(60000);
        }
    }
}