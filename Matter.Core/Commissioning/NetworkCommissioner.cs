using Matter.Core.Certificates;
using Matter.Core.Cryptography;
using Matter.Core.Fabrics;
using Matter.Core.Sessions;
using Matter.Core.TLV;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;

namespace Matter.Core.Commissioning
{
    internal class NetworkCommissioningThread
    {
        private readonly int _discriminator;
        private readonly ManualResetEvent _resetEvent;

        public NetworkCommissioningThread(int number, ManualResetEvent resetEvent)
        {
            _discriminator = number;
            _resetEvent = resetEvent;
        }

        public void PerformDiscovery(object? state)
        {
            if (state is null)
            {
                return;
            }

            Fabric? f = state! as Fabric;

            if (f is null)
            {
                return;
            }

            CommissionOnNetworkDevice(f).Wait();
        }

        private async Task CommissionOnNetworkDevice(Fabric fabric)
        {
            Console.ForegroundColor = ConsoleColor.White;

            if (fabric is null)
            {
                Console.WriteLine("NO FABRIC!");
                return;
            }

            //var discoverer = new DnsDiscoverer();
            //await discoverer.DiscoverCommissionableNodes();

            try
            {
                IConnection udpConnection = new UdpConnection();

                Console.WriteLine("UDP Connection has been established. Starting PASE Exchange....");

                UnsecureSession unsecureSession = new UnsecureSession(udpConnection, 0);

                var unsecureExchange = unsecureSession.CreateExchange();

                // Perform the PASE exchange.
                //
                Console.WriteLine("┌───────────────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 6 - Establish PASE         |");
                Console.WriteLine("| Send PBKDFParamRequest                        |");
                Console.WriteLine("└───────────────────────────────────────────────┘");

                var PBKDFParamRequest = new MatterTLV();
                PBKDFParamRequest.AddStructure();

                // We need a control octet, the tag, the length and the value.
                //
                var initiatorRandomBytes = RandomNumberGenerator.GetBytes(32);
                PBKDFParamRequest.AddOctetString(1, initiatorRandomBytes);
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

                var responseMessageFrame = await unsecureExchange.WaitForNextMessageAsync();

                //Console.WriteLine(responseMessageFrame.MessagePayload.ApplicationPayload.ToString());

                //Console.WriteLine("PBKDFParamResponse received");
                //Console.WriteLine("MessageFlags: {0:X2}\nSessionId: {1:X2}\nSecurityFlags: {2:X2}\nMessageCounter: {3:X2}\nExchangeFlags: {4:X2}\nProtocol OpCode: {5:X2}\nExchange Id: {6:X2}\nProtocolId: {7:X2}",
                //    (byte)responseMessageFrame.MessageFlags,
                //    responseMessageFrame.SessionID,
                //    (byte)responseMessageFrame.SecurityFlags,
                //    responseMessageFrame.MessageCounter,
                //    (byte)responseMessageFrame.MessagePayload.ExchangeFlags,
                //    responseMessageFrame.MessagePayload.ProtocolOpCode,
                //    responseMessageFrame.MessagePayload.ExchangeID,
                //    responseMessageFrame.MessagePayload.ProtocolId
                //);

                // We have to walk the response.
                //
                var PBKDFParamResponse = responseMessageFrame.MessagePayload.ApplicationPayload;

                PBKDFParamResponse.OpenStructure();

                var initiatorRandomBytes2 = PBKDFParamResponse.GetOctetString(1);
                var responderRandomBytes = PBKDFParamResponse.GetOctetString(2);
                var responderSessionId = PBKDFParamResponse.GetUnsignedInt16(3);

                var peerSessionId = responderSessionId;

                //Console.WriteLine("Responder Session Id: {0}", responderSessionId);

                PBKDFParamResponse.OpenStructure(4);

                var iterations = PBKDFParamResponse.GetUnsignedInt16(1);
                var salt = PBKDFParamResponse.GetOctetString(2);

                //Console.WriteLine("Iterations: {0}\nSalt Base64: {1}", iterations, Convert.ToBase64String(salt));

                PBKDFParamResponse.CloseContainer();

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

                //Console.WriteLine(string.Join(",", sessionContextHash));
                //Console.WriteLine("Context: {0}", BitConverter.ToString(SPAKE_CONTEXT));
                //Console.WriteLine("Request: {0}", BitConverter.ToString(PBKDFParamRequest.GetBytes()));
                //Console.WriteLine("Response: {0}", BitConverter.ToString(PBKDFParamResponse.GetBytes()));
                //Console.WriteLine("Hash: {0}", BitConverter.ToString(sessionContextHash));

                // Build the PAKE1 message
                //
                var pake1 = new MatterTLV();
                pake1.AddStructure();

                var (w0, w1, x, X) = CryptographyMethods.Crypto_PAKEValues_Initiator(20202021, iterations, salt);

                var byteString = X.GetEncoded(false).ToArray();

                //Console.WriteLine("Iterations: {0}\nSalt: {1}\nSalt Base64: {2}\npA: {3}", iterations, Encoding.ASCII.GetString(salt), Convert.ToBase64String(salt), Convert.ToBase64String(byteString));

                //Console.WriteLine("X: {0}", BitConverter.ToString(byteString));

                pake1.AddOctetString(1, byteString);

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

                var pake2MessageFrame = await unsecureExchange.WaitForNextMessageAsync();

                //Console.WriteLine("Message received");
                //Console.WriteLine("MessageFlags: {0:X2}\nSessionId: {1:X2}\nSecurityFlags: {2:X2}\nMessageCounter: {3:X2}\nExchangeFlags: {4:X2}\nProtocol OpCode: {5:X2}\nExchange Id: {6:X2}\nProtocolId: {7:X2}",
                //    (byte)pake2MessageFrame.MessageFlags,
                //    pake2MessageFrame.SessionID,
                //    (byte)pake2MessageFrame.SecurityFlags,
                //    pake2MessageFrame.MessageCounter,
                //    (byte)pake2MessageFrame.MessagePayload.ExchangeFlags,
                //    pake2MessageFrame.MessagePayload.ProtocolOpCode,
                //    pake2MessageFrame.MessagePayload.ExchangeID,
                //    pake2MessageFrame.MessagePayload.ProtocolId
                //);

                var pake2 = pake2MessageFrame.MessagePayload.ApplicationPayload;

                pake2.OpenStructure();

                var Y = pake2.GetOctetString(1);
                var Verifier = pake2.GetOctetString(2);

                //Console.WriteLine("Y: {0}", BitConverter.ToString(Y).Replace("-", ""));
                //Console.WriteLine("Verifier: {0}", BitConverter.ToString(Verifier).Replace("-", ""));

                pake2.CloseContainer();

                // Compute Pake3
                //
                var (Ke, hAY, hBX) = CryptographyMethods.Crypto_P2(sessionContextHash, w0, w1, x, X, Y);

                if (!hBX.SequenceEqual(Verifier))
                {
                    throw new Exception("Verifier doesn't match!");
                }

                var pake3 = new MatterTLV();
                pake3.AddStructure();

                pake3.AddOctetString(1, hAY);

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

                var pakeFinishedMessageFrame = await unsecureExchange.WaitForNextMessageAsync();

                //Console.WriteLine("StatusReport received");

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

                //Console.WriteLine("KcAB: {0}", BitConverter.ToString(keys));

                var encryptKey = keys.AsSpan().Slice(0, 16).ToArray();
                var decryptKey = keys.AsSpan().Slice(16, 16).ToArray();
                var attestationKey = keys.AsSpan().Slice(32, 16).ToArray();

                //Console.WriteLine("decryptKey: {0}", BitConverter.ToString(decryptKey));
                //Console.WriteLine("encryptKey: {0}", BitConverter.ToString(encryptKey));
                //Console.WriteLine("attestationKey: {0}", BitConverter.ToString(attestationKey));

                Console.WriteLine("┌─────────────────────────┐");
                Console.WriteLine("| PASE Complete!          |");
                Console.WriteLine(format: "| PeerSessionId: {0} |", peerSessionId);
                Console.WriteLine("└─────────────────────────┘");

                // Create a PASE session
                //
                var paseSession = new PaseSecureSession(udpConnection, peerSessionId, encryptKey, decryptKey);

                // We then create a new Exchange using the secure session.
                //
                var paseExchange = paseSession.CreateExchange();

                #region Vendor Name Command

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
                #endregion

                #region CSRRequest

                Console.WriteLine("┌────────────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 11 - Sending CSRRequest |");
                Console.WriteLine("└────────────────────────────────────────────┘");

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

                csrRequest.AddOctetString(0, csrNonceBytes); // CSRNonce

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

                var csrResponseMessageFrame = await paseExchange.WaitForNextMessageAsync();

                var csrResponsePayload = csrResponseMessageFrame.MessagePayload.ApplicationPayload;

                csrResponsePayload.OpenStructure();
                csrResponsePayload.GetBoolean(0);
                csrResponsePayload.OpenArray(1);

                csrResponsePayload.OpenStructure();
                csrResponsePayload.OpenStructure(0);

                csrResponsePayload.OpenList(0);
                csrResponsePayload.GetUnsignedInt8(0);
                csrResponsePayload.GetUnsignedInt8(1);
                csrResponsePayload.GetUnsignedInt8(2);
                csrResponsePayload.CloseContainer(); // Close list.

                csrResponsePayload.OpenStructure(1);
                var nocsrBytes = csrResponsePayload.GetOctetString(0);

                var nocsrString = Encoding.ASCII.GetString(nocsrBytes.ToArray());

                var nocPayload = new MatterTLV(nocsrBytes);

                //Console.WriteLine("Decoded NOC CSR");
                //Console.WriteLine();
                //Console.WriteLine(nocPayload);

                nocPayload.OpenStructure();
                var derBytes = nocPayload.GetOctetString(1);

                var certificateRequest = new Pkcs10CertificationRequest(derBytes);

                var peerPublicKey = certificateRequest.GetPublicKey();

                var peerNocPublicKey = peerPublicKey as ECPublicKeyParameters;
                var peerNocPublicKeyBytes = peerNocPublicKey.Q.GetEncoded(false);
                var peerNocKeyIdentifier = SHA1.HashData(peerNocPublicKeyBytes).AsSpan().Slice(0, 20).ToArray();

                // Create a self signed certificate!
                //
                var csrInfo = certificateRequest.GetCertificationRequestInfo();
                var certGenerator = new X509V3CertificateGenerator();
                var randomGenerator = new CryptoApiRandomGenerator();
                var random = new SecureRandom(randomGenerator);
                var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);

                var operationalId = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);

                certGenerator.SetSerialNumber(serialNumber);

                var subjectOids = new List<DerObjectIdentifier>();
                var subjectValues = new List<string>();

                subjectOids.Add(new DerObjectIdentifier("1.3.6.1.4.1.37244.1.1")); // NodeId
                subjectOids.Add(new DerObjectIdentifier("1.3.6.1.4.1.37244.1.5")); // FabricId
                subjectValues.Add("ABABABAB00010001");
                subjectValues.Add("FAB000000000001D");

                X509Name subjectDN = new X509Name(subjectOids, subjectValues);

                certGenerator.SetSubjectDN(subjectDN);

                var issuerOids = new List<DerObjectIdentifier>();
                var issuerValues = new List<string>();

                issuerOids.Add(new DerObjectIdentifier("1.3.6.1.4.1.37244.1.4"));
                issuerValues.Add($"CACACACA00000001");

                X509Name issuerDN = new X509Name(issuerOids, issuerValues);

                certGenerator.SetIssuerDN(issuerDN); // The root certificate is the issuer.

                certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
                certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));

                certGenerator.SetPublicKey(certificateRequest.GetPublicKey() as ECPublicKeyParameters);

                // Add the BasicConstraints and SubjectKeyIdentifier extensions
                //
                certGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
                certGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
                certGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.id_kp_clientAuth, KeyPurposeID.id_kp_serverAuth));
                certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(peerNocKeyIdentifier));
                certGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(fabric.RootKeyIdentifier));

                // Create a signature factory for the specified algorithm. Sign the cert with the RootCertificate PrivateyKey
                //
                ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", fabric.RootKeyPair.Private as ECPrivateKeyParameters);
                var peerNoc = certGenerator.Generate(signatureFactory);

                // Write the PEM out to disk
                //
                //using PemWriter pemWriter = new PemWriter(new StreamWriter("h:\\output.pem"));

                //pemWriter.WriteObject(noc);

                //pemWriter.Writer.Flush();

                //File.WriteAllBytes("h:\\output_noc.cer", noc.GetEncoded());

                peerNoc.CheckValidity();

                //Console.WriteLine("NOC Certificate");
                //Console.WriteLine(peerNoc);

                //Console.WriteLine("───────────────── DER ENCODED CERT ────────────────");
                //Console.WriteLine(BitConverter.ToString(peerNoc.GetEncoded()).Replace("-", ""));
                //Console.WriteLine("───────────────────────────────────────────────────");
                //Console.WriteLine();

                await paseExchange.AcknowledgeMessageAsync(csrResponseMessageFrame.MessageCounter);

                #endregion

                #region COMMISSIONING STEP 12 - AddTrustedRootCertificate

                Console.WriteLine("┌───────────────────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 12 - AddTrustedRootCertificate |");
                Console.WriteLine("└───────────────────────────────────────────────────┘");

                paseExchange = paseSession.CreateExchange();

                var encodedRootCertificate = new MatterTLV();
                encodedRootCertificate.AddStructure();

                encodedRootCertificate.AddOctetString(1, fabric.RootCertificate.SerialNumber.ToByteArrayUnsigned()); // SerialNumber
                encodedRootCertificate.AddUInt8(2, 1); // signature-algorithm

                encodedRootCertificate.AddList(3); // Issuer
                encodedRootCertificate.AddUInt64(20, fabric.RootCertificateId.ToByteArrayUnsigned());
                encodedRootCertificate.EndContainer(); // Close List

                var notBefore = new DateTimeOffset(fabric.RootCertificate.NotBefore).ToEpochTime();
                var notAfter = new DateTimeOffset(fabric.RootCertificate.NotAfter).ToEpochTime();

                encodedRootCertificate.AddUInt32(4, (uint)notBefore); // NotBefore
                encodedRootCertificate.AddUInt32(5, (uint)notAfter); // NotAfter

                encodedRootCertificate.AddList(6); // Subject
                //encodedRootCertificate.AddUInt64(17, fabric.RootNodeId.ToByteArrayUnsigned());
                encodedRootCertificate.AddUInt64(20, fabric.RootCertificateId.ToByteArrayUnsigned());
                encodedRootCertificate.EndContainer(); // Close List

                encodedRootCertificate.AddUInt8(7, 1); // public-key-algorithm
                encodedRootCertificate.AddUInt8(8, 1); // elliptic-curve-id

                var rootPublicKey = fabric.RootCertificate.GetPublicKey() as ECPublicKeyParameters;
                var rootPublicKeyBytes = rootPublicKey!.Q.GetEncoded(false);
                encodedRootCertificate.AddOctetString(9, rootPublicKeyBytes); // PublicKey

                //Console.WriteLine("Root Certificate PublicKey: {0}", BitConverter.ToString(rootPublicKeyBytes).Replace("-", ""));

                encodedRootCertificate.AddList(10); // Extensions

                encodedRootCertificate.AddStructure(1); // Basic Constraints
                encodedRootCertificate.AddBool(1, true); // is-ca
                encodedRootCertificate.EndContainer(); // Close Basic Constraints

                // 6.5.11.2.Key Usage Extension We want keyCertSign (0x20) and CRLSign (0x40)
                encodedRootCertificate.AddUInt8(2, 0x60);

                encodedRootCertificate.AddOctetString(4, fabric.RootKeyIdentifier); // subject-key-id
                encodedRootCertificate.AddOctetString(5, fabric.RootKeyIdentifier); // authority-key-id

                encodedRootCertificate.EndContainer(); // Close Extensions

                //Console.WriteLine(fabric.RootCertificate);

                //Console.WriteLine("───────────────── DER ENCODED CERT ────────────────");
                //Console.WriteLine(BitConverter.ToString(fabric.RootCertificate.GetEncoded()).Replace("-", ""));
                //Console.WriteLine("───────────────────────────────────────────────────");
                //Console.WriteLine();

                // Signature. This is an ASN1 EC Signature that is DER encoded.
                // The Matter specification just wants the two parts r & s.
                //
                var signature = fabric.RootCertificate.GetSignature();
                //Console.WriteLine("Signature: {0}", BitConverter.ToString(signature));

                // We need to convert this signature into a TLV format.
                //
                AsnDecoder.ReadSequence(signature.AsSpan(), AsnEncodingRules.DER, out var offset, out var length, out _);

                var source = signature.AsSpan().Slice(offset, length).ToArray();

                var r = AsnDecoder.ReadInteger(source, AsnEncodingRules.DER, out var bytesConsumed);
                var s = AsnDecoder.ReadInteger(source.AsSpan().Slice(bytesConsumed), AsnEncodingRules.DER, out bytesConsumed);

                var encodedRootCertificateSignature = r.ToByteArray(isUnsigned: true, isBigEndian: true).Concat(s.ToByteArray(isUnsigned: true, isBigEndian: true)).ToArray();

                encodedRootCertificate.AddOctetString(11, encodedRootCertificateSignature);

                encodedRootCertificate.EndContainer(); // Close Structure

                //Console.WriteLine("───────────────────────────────────────────────────");
                //Console.WriteLine("EncodedRootCertificate");
                //Console.WriteLine(encodedRootCertificate);
                //Console.WriteLine("───────────────────────────────────────────────────");

                var addTrustedRootCertificateRequest = new MatterTLV();
                addTrustedRootCertificateRequest.AddStructure();
                addTrustedRootCertificateRequest.AddBool(0, false);
                addTrustedRootCertificateRequest.AddBool(1, false);
                addTrustedRootCertificateRequest.AddArray(tagNumber: 2); // InvokeRequests

                addTrustedRootCertificateRequest.AddStructure();

                addTrustedRootCertificateRequest.AddList(tagNumber: 0); // CommandPath

                addTrustedRootCertificateRequest.AddUInt16(tagNumber: 0, 0x00); // Endpoint 0x00
                addTrustedRootCertificateRequest.AddUInt32(tagNumber: 1, 0x3E); // ClusterId 0x3E - Node Operational Credentials
                addTrustedRootCertificateRequest.AddUInt16(tagNumber: 2, 0x0B); // 11.18.6. Command AddTrustedRootCertificate

                addTrustedRootCertificateRequest.EndContainer();

                addTrustedRootCertificateRequest.AddStructure(1); // CommandFields

                addTrustedRootCertificateRequest.AddOctetString(0, encodedRootCertificate.GetBytes()); // RootCertificate

                addTrustedRootCertificateRequest.EndContainer(); // Close the CommandFields

                addTrustedRootCertificateRequest.EndContainer(); // Close the structure

                addTrustedRootCertificateRequest.EndContainer(); // Close the array

                addTrustedRootCertificateRequest.AddUInt8(255, 12); // interactionModelRevision

                addTrustedRootCertificateRequest.EndContainer(); // Close the structure




                var addTrustedRootCertificateRequestMessagePayload = new MessagePayload(addTrustedRootCertificateRequest);

                addTrustedRootCertificateRequestMessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                // Table 14. Protocol IDs for the Matter Standard Vendor ID
                addTrustedRootCertificateRequestMessagePayload.ProtocolId = 0x01; // IM Protocol Messages
                addTrustedRootCertificateRequestMessagePayload.ProtocolOpCode = 0x08; // InvokeRequest

                var addTrustedRootCerticateRequestMessageFrame = new MessageFrame(addTrustedRootCertificateRequestMessagePayload);

                // TODO Send this using MRP.
                addTrustedRootCerticateRequestMessageFrame.MessageFlags |= MessageFlags.S;
                addTrustedRootCerticateRequestMessageFrame.SecurityFlags = 0x00;
                addTrustedRootCerticateRequestMessageFrame.SourceNodeID = 0x00;

                await paseExchange.SendAsync(addTrustedRootCerticateRequestMessageFrame);

                var addTrustedRootCertificateResponseMessageFrame = await paseExchange.WaitForNextMessageAsync();

                await paseExchange.AcknowledgeMessageAsync(addTrustedRootCerticateRequestMessageFrame.MessageCounter);

                #endregion

                #region COMMISSIONING STEP 13 - AddNocRequest

                // Perform Step 13 of the Commissioning Flow.
                //
                Console.WriteLine("┌───────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 13 - AddNocRequest |");
                Console.WriteLine("└───────────────────────────────────────┘");

                paseExchange = paseSession.CreateExchange();

                // Encode the NOC.
                //
                var encodedPeerNocCertificate = new MatterTLV();
                encodedPeerNocCertificate.AddStructure();

                encodedPeerNocCertificate.AddOctetString(1, peerNoc.SerialNumber.ToByteArrayUnsigned()); // SerialNumber
                encodedPeerNocCertificate.AddUInt8(2, 1); // signature-algorithm

                encodedPeerNocCertificate.AddList(3); // Issuer
                encodedPeerNocCertificate.AddUInt64(20, fabric.RootCertificateId.ToByteArrayUnsigned());
                encodedPeerNocCertificate.EndContainer(); // Close List

                notBefore = new DateTimeOffset(peerNoc.NotBefore).ToEpochTime();
                notAfter = new DateTimeOffset(peerNoc.NotAfter).ToEpochTime();

                encodedPeerNocCertificate.AddUInt32(4, (uint)notBefore); // NotBefore
                encodedPeerNocCertificate.AddUInt32(5, (uint)notAfter); // NotAfter

                encodedPeerNocCertificate.AddList(6); // Subject

                var peerNodeIdBytes = "ABABABAB00010001".ToByteArray();
                var peerNodeId = new BigInteger(peerNodeIdBytes, false);

                encodedPeerNocCertificate.AddUInt64(17, peerNodeId.ToByteArrayUnsigned()); // NodeId
                encodedPeerNocCertificate.AddUInt64(21, fabric.FabricId.ToByteArrayUnsigned()); // FabricId

                encodedPeerNocCertificate.EndContainer(); // Close List

                encodedPeerNocCertificate.AddUInt8(7, 1); // public-key-algorithm
                encodedPeerNocCertificate.AddUInt8(8, 1); // elliptic-curve-id

                encodedPeerNocCertificate.AddOctetString(9, peerNocPublicKeyBytes); // PublicKey

                encodedPeerNocCertificate.AddList(10); // Extensions

                encodedPeerNocCertificate.AddStructure(1); // Basic Constraints
                encodedPeerNocCertificate.AddBool(1, false); // is-ca
                encodedPeerNocCertificate.EndContainer(); // Close Basic Constraints

                encodedPeerNocCertificate.AddUInt8(2, 0x1);

                encodedPeerNocCertificate.AddArray(3); // Extended Key Usage
                encodedPeerNocCertificate.AddUInt8(0x02);
                encodedPeerNocCertificate.AddUInt8(0x01);
                encodedPeerNocCertificate.EndContainer();

                encodedPeerNocCertificate.AddOctetString(4, peerNocKeyIdentifier); // subject-key-id
                encodedPeerNocCertificate.AddOctetString(5, fabric.RootKeyIdentifier); // authority-key-id

                encodedPeerNocCertificate.EndContainer(); // Close Extensions

                // Signature. This is an ASN1 EC Signature that is DER encoded.
                // The Matter specification just wants the two parts r & s.
                //
                var peerNocSignature = peerNoc.GetSignature();
                //Console.WriteLine("Signature: {0}", BitConverter.ToString(signature));

                // We need to convert this signature into a TLV format.
                //
                AsnDecoder.ReadSequence(peerNocSignature.AsSpan(), AsnEncodingRules.DER, out offset, out length, out _);

                source = peerNocSignature.AsSpan().Slice(offset, length).ToArray();

                r = AsnDecoder.ReadInteger(source, AsnEncodingRules.DER, out bytesConsumed);
                s = AsnDecoder.ReadInteger(source.AsSpan().Slice(bytesConsumed), AsnEncodingRules.DER, out bytesConsumed);

                var encodedPeerNocCertificateSignature = r.ToByteArray(isUnsigned: true, isBigEndian: true).Concat(s.ToByteArray(isUnsigned: true, isBigEndian: true)).ToArray();

                encodedPeerNocCertificate.AddOctetString(11, encodedPeerNocCertificateSignature);

                encodedPeerNocCertificate.EndContainer(); // Close Structure

                //Console.WriteLine("───────────────────────────────────────────────────");
                //Console.WriteLine("Encoded NOC");
                //Console.WriteLine(encodedPeerNocCertificate);
                //Console.WriteLine("───────────────────────────────────────────────────");

                var addNocRequest = new MatterTLV();
                addNocRequest.AddStructure();
                addNocRequest.AddBool(0, false);
                addNocRequest.AddBool(1, false);
                addNocRequest.AddArray(tagNumber: 2); // InvokeRequests

                addNocRequest.AddStructure();

                addNocRequest.AddList(tagNumber: 0); // CommandPath

                addNocRequest.AddUInt16(tagNumber: 0, 0x00); // Endpoint 0x00
                addNocRequest.AddUInt32(tagNumber: 1, 0x3E); // ClusterId 0x3E - Node Operational Credentials
                addNocRequest.AddUInt16(tagNumber: 2, 0x06); // 11.18.6. Command AddNoc

                addNocRequest.EndContainer();

                addNocRequest.AddStructure(1); // CommandFields

                addNocRequest.AddOctetString(0, encodedPeerNocCertificate.GetBytes()); // NOCValue
                addNocRequest.AddOctetString(2, fabric.IPK); // IPKValue
                addNocRequest.AddUInt64(3, fabric.RootNodeId.ToByteArrayUnsigned()); // CaseAdminSubject - In this case the RootNodeId.
                addNocRequest.AddUInt16(4, fabric.AdminVendorId); // AdminVendorId

                addNocRequest.EndContainer(); // Close the CommandFields

                addNocRequest.EndContainer(); // Close the structure

                addNocRequest.EndContainer(); // Close the array

                addNocRequest.AddUInt8(255, 12); // interactionModelRevision

                addNocRequest.EndContainer(); // Close the structure

                var addNocRequestMessagePayload = new MessagePayload(addNocRequest);

                addNocRequestMessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                // Table 14. Protocol IDs for the Matter Standard Vendor ID
                addNocRequestMessagePayload.ProtocolId = 0x01; // IM Protocol Messages
                addNocRequestMessagePayload.ProtocolOpCode = 0x08; // InvokeRequest

                var addNocRequestMessageFrame = new MessageFrame(addNocRequestMessagePayload);

                // TODO Send this using MRP.
                addNocRequestMessageFrame.MessageFlags |= MessageFlags.S;
                addNocRequestMessageFrame.SecurityFlags = 0x00;
                addNocRequestMessageFrame.SourceNodeID = 0x00;

                await paseExchange.SendAsync(addNocRequestMessageFrame);

                var addNocResponseMessageFrame = await paseExchange.WaitForNextMessageAsync();

                // Acknowledge the response.
                //
                await paseExchange.AcknowledgeMessageAsync(addNocResponseMessageFrame.MessageCounter);

                // We're done with PASE, so close the exchange.
                //
                paseExchange.Close();

                #endregion

                #region COMMISSIONING STEP 20 - CASE

                Console.WriteLine("┌───────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 20 - CASE - Sigma1 |");
                Console.WriteLine("└───────────────────────────────────────┘");

                // Create a new Exchange over the unsecure session.
                //
                paseExchange = unsecureSession.CreateExchange();

                // Exchange CASE Messages, starting with Sigma1
                //
                var spake1InitiatorRandomBytes = RandomNumberGenerator.GetBytes(32);
                var spake1SessionId = RandomNumberGenerator.GetBytes(16);

                //Console.WriteLine("Spake1InitiatorRandomBytes: {0}", BitConverter.ToString(spake1InitiatorRandomBytes).Replace("-", ""));

                var ephermeralKeys = CertificateAuthority.GenerateKeyPair();
                var ephermeralPublicKey = ephermeralKeys.Public as ECPublicKeyParameters;
                var ephermeralPrivateKey = ephermeralKeys.Private as ECPrivateKeyParameters;
                var ephermeralPublicKeysBytes = ephermeralPublicKey.Q.GetEncoded(false);

                //Console.WriteLine("RootPublicKeyBytes: {0}", BitConverter.ToString(rootPublicKeyBytes).Replace("-", ""));
                //Console.WriteLine("NocPublicKeyBytes: {0}", BitConverter.ToString(nocPublicKeyBytes).Replace("-", ""));
                //Console.WriteLine("EphermeralKeysBytes: {0}", BitConverter.ToString(ephermeralKeysBytes).Replace("-", ""));

                // Destination identifier is a composite.
                //
                MemoryStream ms = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(ms);
                writer.Write(spake1InitiatorRandomBytes);
                writer.Write(rootPublicKeyBytes);
                writer.Write(fabric.FabricId.ToByteArrayUnsigned());
                writer.Write(peerNodeId.ToByteArrayUnsigned());

                var destinationId = ms.ToArray();

                var hmac = new HMACSHA256(fabric.OperationalIPK);
                byte[] hashedDestinationId = hmac.ComputeHash(destinationId);

                var sigma1Payload = new MatterTLV();
                sigma1Payload.AddStructure();

                sigma1Payload.AddOctetString(1, spake1InitiatorRandomBytes); // initiatorRandom
                sigma1Payload.AddUInt16(2, BitConverter.ToUInt16(spake1SessionId)); // initiatorSessionId 
                sigma1Payload.AddOctetString(3, hashedDestinationId); // destinationId
                sigma1Payload.AddOctetString(4, ephermeralPublicKeysBytes); // initiatorEphPubKey

                sigma1Payload.EndContainer();

                var sigma1MessagePayload = new MessagePayload(sigma1Payload);

                sigma1MessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                sigma1MessagePayload.ProtocolId = 0x00;
                sigma1MessagePayload.ProtocolOpCode = 0x30; // Sigma1

                var sigma1MessageFrame = new MessageFrame(sigma1MessagePayload);

                sigma1MessageFrame.MessageFlags |= MessageFlags.S;
                sigma1MessageFrame.SecurityFlags = 0x00;
                sigma1MessageFrame.SourceNodeID = 0x00;

                await paseExchange.SendAsync(sigma1MessageFrame);

                Console.WriteLine("┌───────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 20 - CASE - Sigma2 |");
                Console.WriteLine("└───────────────────────────────────────┘");

                var sigma2MessageFrame = await paseExchange.WaitForNextMessageAsync();

                var sigma2Payload = sigma2MessageFrame.MessagePayload.ApplicationPayload;

                sigma2Payload.OpenStructure();

                var sigma2ResponderRandom = sigma2Payload.GetOctetString(1);
                var sigma2ResponderSessionId = sigma2Payload.GetUnsignedInt16(2);
                var sigma2ResponderEphPublicKey = sigma2Payload.GetOctetString(3);
                var sigma2EncryptedPayload = sigma2Payload.GetOctetString(4);

                // Generate the shared secret.
                //
                var sigmaKeyAgreement = AgreementUtilities.GetBasicAgreement("ECDH");
                sigmaKeyAgreement.Init(ephermeralPrivateKey);

                var curve = ECNamedCurveTable.GetByName("P-256");
                var ecPoint = curve.Curve.DecodePoint(sigma2ResponderEphPublicKey);
                var ephPublicKey = new ECPublicKeyParameters(ecPoint, new ECDomainParameters(curve));

                var sharedSecretResult = sigmaKeyAgreement.CalculateAgreement(ephPublicKey);
                var sharedSecret = sharedSecretResult.ToByteArrayUnsigned();

                Console.WriteLine("CASE SharedSecret: {0}", BitConverter.ToString(sharedSecret).Replace("-", ""));

                // Generate the shared key using HKDF
                //
                // Step 1 - the TranscriptHash
                //
                var transcriptHash = SHA256.HashData(sigma1Payload.GetBytes());

                // Step 2 - SALT
                ms = new MemoryStream();
                BinaryWriter saltWriter = new BinaryWriter(ms);
                saltWriter.Write(fabric.OperationalIPK);
                saltWriter.Write(sigma2ResponderRandom);
                saltWriter.Write(sigma2ResponderEphPublicKey);
                saltWriter.Write(transcriptHash);

                salt = ms.ToArray();

                // Step 3 - Compute the S2K (the shared key)
                //
                info = Encoding.ASCII.GetBytes("Sigma2");

                hkdf = new HkdfBytesGenerator(new Sha256Digest());
                hkdf.Init(new HkdfParameters(sharedSecret, salt, info));

                var sigma2Key = new byte[16];
                hkdf.GenerateBytes(sigma2Key, 0, 16);

                Console.WriteLine(format: "S2K: {0}", BitConverter.ToString(sigma2Key).Replace("-", ""));

                // Step 4 - Use the S2K to decrypt the payload
                // 
                var nonce = Encoding.ASCII.GetBytes("NCASE_Sigma2N");

                IBlockCipher cipher = new AesEngine();
                int macSize = 8 * cipher.GetBlockSize();

                AeadParameters keyParamAead = new AeadParameters(new KeyParameter(sigma2Key), macSize, nonce);
                CcmBlockCipher cipherMode = new CcmBlockCipher(cipher);
                cipherMode.Init(false, keyParamAead);

                var outputSize = cipherMode.GetOutputSize(sigma2EncryptedPayload.Length);
                var plainTextData = new byte[outputSize];
                var result = cipherMode.ProcessBytes(sigma2EncryptedPayload, 0, sigma2EncryptedPayload.Length, plainTextData, 0);
                cipherMode.DoFinal(plainTextData, result);

                var TBEData2 = new MatterTLV(plainTextData);

                //Console.WriteLine(TBEData2);

                // TODO Verify this!

                Console.WriteLine("┌───────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 20 - CASE - Sigma3 |");
                Console.WriteLine("└───────────────────────────────────────┘");

                // First, generate a signature for our NOC
                //
                var nocSignature = fabric.OperationalCertificate.GetSignature();

                // We need to convert this signature into a TLV format.
                //
                AsnDecoder.ReadSequence(nocSignature.AsSpan(), AsnEncodingRules.DER, out offset, out length, out _);

                source = nocSignature.AsSpan().Slice(offset, length).ToArray();

                r = AsnDecoder.ReadInteger(source, AsnEncodingRules.DER, out bytesConsumed);
                s = AsnDecoder.ReadInteger(source.AsSpan().Slice(bytesConsumed), AsnEncodingRules.DER, out bytesConsumed);

                var encodedNocCertificateSignature = r.ToByteArray(isUnsigned: true, isBigEndian: true).Concat(s.ToByteArray(isUnsigned: true, isBigEndian: true)).ToArray();

                // Encode the certificate.
                var encodedNocCertificate = new MatterTLV();
                encodedNocCertificate.AddStructure();

                encodedNocCertificate.AddOctetString(1, fabric.OperationalCertificate.SerialNumber.ToByteArrayUnsigned()); // SerialNumber
                encodedNocCertificate.AddUInt8(2, 1); // signature-algorithm

                encodedNocCertificate.AddList(3); // Issuer
                encodedNocCertificate.AddUInt64(20, fabric.RootCertificateId.ToByteArrayUnsigned());
                encodedNocCertificate.EndContainer(); // Close List

                notBefore = new DateTimeOffset(fabric.OperationalCertificate.NotBefore).ToEpochTime();
                notAfter = new DateTimeOffset(fabric.OperationalCertificate.NotAfter).ToEpochTime();

                encodedNocCertificate.AddUInt32(4, (uint)notBefore); // NotBefore
                encodedNocCertificate.AddUInt32(5, (uint)notAfter); // NotAfter

                encodedNocCertificate.AddList(6); // Subject

                encodedNocCertificate.AddUInt64(17, fabric.RootNodeId.ToByteArrayUnsigned()); // NodeId
                encodedNocCertificate.AddUInt64(21, fabric.FabricId.ToByteArrayUnsigned()); // FabricId

                encodedNocCertificate.EndContainer(); // Close List

                encodedNocCertificate.AddUInt8(7, 1); // public-key-algorithm
                encodedNocCertificate.AddUInt8(8, 1); // elliptic-curve-id

                var nocPublicKey = fabric.OperationalCertificate.GetPublicKey() as ECPublicKeyParameters;
                var nocPublicKeyBytes = nocPublicKey.Q.GetEncoded(false);
                encodedNocCertificate.AddOctetString(9, nocPublicKeyBytes); // PublicKey

                encodedNocCertificate.AddList(10); // Extensions

                encodedNocCertificate.AddStructure(1); // Basic Constraints
                encodedNocCertificate.AddBool(1, false); // is-ca
                encodedNocCertificate.EndContainer(); // Close Basic Constraints

                encodedNocCertificate.AddUInt8(2, 0x1);

                encodedNocCertificate.AddArray(3); // Extended Key Usage
                encodedNocCertificate.AddUInt8(0x02);
                encodedNocCertificate.AddUInt8(0x01);
                encodedNocCertificate.EndContainer();

                var nocKeyIdentifier = SHA1.HashData(nocPublicKeyBytes).AsSpan().Slice(0, 20).ToArray();

                encodedNocCertificate.AddOctetString(4, nocKeyIdentifier); // subject-key-id
                encodedNocCertificate.AddOctetString(5, fabric.RootKeyIdentifier); // authority-key-id

                encodedNocCertificate.EndContainer(); // Close Extensions

                encodedNocCertificate.AddOctetString(11, encodedNocCertificateSignature);

                encodedNocCertificate.EndContainer(); // Close Structure

                //Console.WriteLine("───────────────────────────────────────────────────");
                //Console.WriteLine(encodedNocCertificate);
                //Console.WriteLine("───────────────────────────────────────────────────");

                // Build sigma-3-tbsdata
                //
                var sigma3tbs = new MatterTLV();

                sigma3tbs.AddStructure();

                sigma3tbs.AddOctetString(1, encodedNocCertificate.GetBytes()); // initiatorNOC
                sigma3tbs.AddOctetString(3, ephermeralPublicKeysBytes); // initiatorEphPubKey
                sigma3tbs.AddOctetString(4, sigma2ResponderEphPublicKey); // responderEphPubKey

                sigma3tbs.EndContainer();

                var sigma3tbsBytes = sigma3tbs.GetBytes();

                //Console.WriteLine("sigma3tbsBytes {0}", BitConverter.ToString(sigma3tbsBytes).Replace("-", ""));

                // Sign this tbsData3.
                //
                var signer = SignerUtilities.GetSigner("SHA256WITHECDSA");
                signer.Init(true, fabric.OperationalCertificateKeyPair.Private as ECPrivateKeyParameters);
                signer.BlockUpdate(sigma3tbsBytes, 0, sigma3tbsBytes.Length);
                byte[] sigma3tbsSignature = signer.GenerateSignature();

                //Console.WriteLine("sigma3tbsSignature {0}", BitConverter.ToString(sigma3tbsSignature).Replace("-", ""));

                // Convert from an ASN.1 signature to a TLV encoded one.
                //
                AsnDecoder.ReadSequence(sigma3tbsSignature.AsSpan(), AsnEncodingRules.DER, out offset, out length, out _);

                source = sigma3tbsSignature.AsSpan().Slice(offset, length).ToArray();

                r = AsnDecoder.ReadInteger(source, AsnEncodingRules.DER, out bytesConsumed);
                s = AsnDecoder.ReadInteger(source.AsSpan().Slice(bytesConsumed), AsnEncodingRules.DER, out bytesConsumed);

                var encodedSigma3TbsSignature = r.ToByteArray(isUnsigned: true, isBigEndian: true).Concat(s.ToByteArray(isUnsigned: true, isBigEndian: true)).ToArray();

                // Construct the sigma-3-tbe payload, which will be encrypted.
                //
                var sigma3tbe = new MatterTLV();
                sigma3tbe.AddStructure();
                sigma3tbe.AddOctetString(1, encodedNocCertificate.GetBytes());
                sigma3tbe.AddOctetString(3, encodedSigma3TbsSignature);
                sigma3tbe.EndContainer();

                //Console.WriteLine("sigma1Bytes {0}", BitConverter.ToString(sigma1Payload.GetBytes()).Replace("-", ""));
                //Console.WriteLine("sigma2Bytes {0}", BitConverter.ToString(sigma2Payload.GetBytes()).Replace("-", ""));

                var sigma3tbeTranscriptHash = SHA256.HashData(sigma1Payload.GetBytes().Concat(sigma2Payload.GetBytes()).ToArray());

                Console.WriteLine("S3 TranscriptHash {0}", BitConverter.ToString(sigma3tbeTranscriptHash).Replace("-", ""));

                ms = new MemoryStream();
                saltWriter = new BinaryWriter(ms);
                saltWriter.Write(fabric.OperationalIPK);
                saltWriter.Write(sigma3tbeTranscriptHash);

                salt = ms.ToArray();

                Console.WriteLine("S3 Salt {0}", BitConverter.ToString(salt).Replace("-", ""));

                // Step 3 - Compute the S3K (the shared key)
                //
                info = Encoding.ASCII.GetBytes("Sigma3");

                hkdf = new HkdfBytesGenerator(new Sha256Digest());
                hkdf.Init(new HkdfParameters(sharedSecret, salt, info));

                var sigma3Key = new byte[16];
                hkdf.GenerateBytes(sigma3Key, 0, 16);

                Console.WriteLine(format: "S3K: {0}", BitConverter.ToString(sigma3Key).Replace("-", ""));

                nonce = Encoding.ASCII.GetBytes("NCASE_Sigma3N");

                keyParamAead = new AeadParameters(new KeyParameter(sigma3Key), macSize, nonce);
                cipherMode = new CcmBlockCipher(cipher);
                cipherMode.Init(true, keyParamAead);

                var sigma3tbeBytes = sigma3tbe.GetBytes();

                outputSize = cipherMode.GetOutputSize(sigma3tbeBytes.Length);
                var encryptedData = new byte[outputSize];
                result = cipherMode.ProcessBytes(sigma3tbeBytes, 0, sigma3tbeBytes.Length, encryptedData, 0);
                cipherMode.DoFinal(encryptedData, result);

                Console.WriteLine("-");
                Console.WriteLine(format: "NocPublicKey: {0}", BitConverter.ToString(nocPublicKeyBytes).Replace("-", ""));
                Console.WriteLine("-");
                Console.WriteLine(format: "Noc: {0}", BitConverter.ToString(encodedNocCertificate.GetBytes()).Replace("-", ""));
                Console.WriteLine("-");
                Console.WriteLine(format: "SignatureData: {0}", BitConverter.ToString(sigma3tbsBytes).Replace("-", ""));
                Console.WriteLine("-");
                Console.WriteLine(format: "Signature: {0}", BitConverter.ToString(encodedNocCertificateSignature).Replace("-", ""));
                Console.WriteLine("-");
                Console.WriteLine(format: "S3 Data: {0}", BitConverter.ToString(sigma3tbeBytes).Replace("-", ""));
                Console.WriteLine("-");
                Console.WriteLine(format: "S3 Encrypted: {0}", BitConverter.ToString(encryptedData).Replace("-", ""));
                Console.WriteLine("-");

                var sigma3Payload = new MatterTLV();
                sigma3Payload.AddStructure();
                sigma3Payload.AddOctetString(1, encryptedData); // sigma3EncryptedPayload
                sigma3Payload.EndContainer();

                var sigma3MessagePayload = new MessagePayload(sigma3Payload);

                sigma3MessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                sigma3MessagePayload.ProtocolId = 0x00;
                sigma3MessagePayload.ProtocolOpCode = 0x32; // Sigma3

                var sigma3MessageFrame = new MessageFrame(sigma3MessagePayload);

                sigma3MessageFrame.MessageFlags |= MessageFlags.S;
                sigma3MessageFrame.SecurityFlags = 0x00;
                sigma3MessageFrame.SourceNodeID = 0x00;

                await paseExchange.SendAsync(sigma3MessageFrame);

                var successMessageFrame = await paseExchange.WaitForNextMessageAsync();

                await paseExchange.AcknowledgeMessageAsync(successMessageFrame.MessageCounter);

                //Console.WriteLine("operationalIdentityProtectionKey: {0}", BitConverter.ToString(fabric.OperationalIPK).Replace("-", ""));
                //Console.WriteLine("sigma1Bytes: {0}", BitConverter.ToString(sigma1Payload.GetBytes()).Replace("-", ""));
                //Console.WriteLine("sigma2Bytes: {0}", BitConverter.ToString(sigma2Payload.GetBytes()).Replace("-", ""));
                //Console.WriteLine("sigma3Bytes: {0}", BitConverter.ToString(sigma3Payload.GetBytes()).Replace("-", ""));

                byte[] caseInfo = Encoding.ASCII.GetBytes("SessionKeys");

                ms = new MemoryStream();
                var transcriptWriter = new BinaryWriter(ms);
                transcriptWriter.Write(sigma1Payload.GetBytes());
                transcriptWriter.Write(sigma2Payload.GetBytes());
                transcriptWriter.Write(sigma3Payload.GetBytes());

                transcriptHash = SHA256.HashData(ms.ToArray());

                //Console.WriteLine(format: "hash: {0}", BitConverter.ToString(transcriptHash).Replace("-", ""));

                ms = new MemoryStream();
                saltWriter = new BinaryWriter(ms);
                saltWriter.Write(fabric.OperationalIPK);
                saltWriter.Write(transcriptHash);

                var secureSessionSalt = ms.ToArray();

                //Console.WriteLine("sharedSecret: {0}", BitConverter.ToString(sharedSecret).Replace("-", ""));
                //Console.WriteLine("salt: {0}", BitConverter.ToString(secureSessionSalt).Replace("-", ""));

                hkdf = new HkdfBytesGenerator(new Sha256Digest());
                hkdf.Init(new HkdfParameters(sharedSecret, secureSessionSalt, caseInfo));

                var caseKeys = new byte[48];
                hkdf.GenerateBytes(caseKeys, 0, 48);

                encryptKey = caseKeys.AsSpan().Slice(0, 16).ToArray();
                decryptKey = caseKeys.AsSpan().Slice(16, 16).ToArray();
                attestationKey = caseKeys.AsSpan().Slice(32, 16).ToArray();

                Console.WriteLine("decryptKey: {0}", BitConverter.ToString(decryptKey).Replace("-", ""));
                Console.WriteLine("encryptKey: {0}", BitConverter.ToString(encryptKey).Replace("-", ""));
                Console.WriteLine("attestationKey: {0}", BitConverter.ToString(attestationKey).Replace("-", ""));

                #endregion

                Console.WriteLine("┌───────────────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 21 - CommissioningComplete |");
                Console.WriteLine("└───────────────────────────────────────────────┘");

                udpConnection = new UdpConnection();
                var caseSession = new CaseSecureSession(udpConnection,
                                                        BitConverter.ToUInt64(fabric.RootNodeId.ToByteArrayUnsigned()),
                                                        BitConverter.ToUInt64(peerNodeId.ToByteArrayUnsigned()),
                                                        sigma2ResponderSessionId,
                                                        encryptKey,
                                                        decryptKey);

                // We then create a new Exchange using the secure session.
                //
                var caseExchange = caseSession.CreateExchange();

                //await caseExchange.AcknowledgeMessageAsync(successMessageFrame.MessageCounter);

                var commissioningCompletePayload = new MatterTLV();
                commissioningCompletePayload.AddStructure();
                commissioningCompletePayload.AddBool(0, false);
                commissioningCompletePayload.AddBool(1, false);
                commissioningCompletePayload.AddArray(tagNumber: 2); // InvokeRequests

                commissioningCompletePayload.AddStructure();

                commissioningCompletePayload.AddList(tagNumber: 0); // CommandPath

                commissioningCompletePayload.AddUInt16(tagNumber: 0, 0x00); // Endpoint 0x00
                commissioningCompletePayload.AddUInt32(tagNumber: 1, 0x30); // ClusterId 0x30 - General Commissioning
                commissioningCompletePayload.AddUInt16(tagNumber: 2, 0x04); // 11.18.6. Command CompleteCommissioning

                commissioningCompletePayload.EndContainer();

                commissioningCompletePayload.AddStructure(1); // CommandFields
                commissioningCompletePayload.EndContainer(); // Close the CommandFields

                commissioningCompletePayload.EndContainer(); // Close the structure

                commissioningCompletePayload.EndContainer(); // Close the array

                commissioningCompletePayload.AddUInt8(255, 12); // interactionModelRevision

                commissioningCompletePayload.EndContainer(); // Close the structure

                var commissioningCompleteMessagePayload = new MessagePayload(commissioningCompletePayload);

                commissioningCompleteMessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                // Table 14. Protocol IDs for the Matter Standard Vendor ID
                commissioningCompleteMessagePayload.ProtocolId = 0x01; // IM Protocol Messages
                commissioningCompleteMessagePayload.ProtocolOpCode = 0x08; // InvokeRequest

                var commissioningCompleteMessageFrame = new MessageFrame(commissioningCompleteMessagePayload);

                commissioningCompleteMessageFrame.MessageFlags |= MessageFlags.S;
                commissioningCompleteMessageFrame.SecurityFlags = 0x00;
                commissioningCompleteMessageFrame.SourceNodeID = BitConverter.ToUInt64(fabric.RootNodeId.ToByteArrayUnsigned());
                commissioningCompleteMessageFrame.DestinationNodeId = BitConverter.ToUInt64(peerNodeId.ToByteArrayUnsigned());

                await caseExchange.SendAsync(commissioningCompleteMessageFrame);

                var commissioningCompleteResponseMessageFrame = await caseExchange.WaitForNextMessageAsync();

                await caseExchange.AcknowledgeMessageAsync(commissioningCompleteResponseMessageFrame.MessageCounter);

                Console.WriteLine("┌───────────────────────────────────────────────┐");
                Console.WriteLine("| Commissioning of Node {0} is complete |", peerNodeId.LongValue);
                Console.WriteLine("└───────────────────────────────────────────────┘");

                await fabric.AddCommissionedNodeAsync(peerNodeId, nocPublicKey);

                await Task.Delay(5000);

                Console.WriteLine("┌─────────────────────┐");
                Console.WriteLine("| Let there be light! |");
                Console.WriteLine("└─────────────────────┘");

                caseExchange = caseSession.CreateExchange();

                var onCommandPayload = new MatterTLV();
                onCommandPayload.AddStructure();
                onCommandPayload.AddBool(0, false);
                onCommandPayload.AddBool(1, false);
                onCommandPayload.AddArray(tagNumber: 2); // InvokeRequests

                onCommandPayload.AddStructure();

                onCommandPayload.AddList(tagNumber: 0); // CommandPath

                onCommandPayload.AddUInt16(tagNumber: 0, 0x01); // Endpoint 0x01
                onCommandPayload.AddUInt32(tagNumber: 1, 0x06); // ClusterId 0x06 - OnOff
                onCommandPayload.AddUInt16(tagNumber: 2, 0x01); // 1.5.7 Command On

                onCommandPayload.EndContainer();

                onCommandPayload.AddStructure(1); // CommandFields
                onCommandPayload.EndContainer(); // Close the CommandFields

                onCommandPayload.EndContainer(); // Close the structure

                onCommandPayload.EndContainer(); // Close the array

                onCommandPayload.AddUInt8(255, 12); // interactionModelRevision

                onCommandPayload.EndContainer(); // Close the structure

                var onCommandPayloadMessagePayload = new MessagePayload(onCommandPayload);

                onCommandPayloadMessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                // Table 14. Protocol IDs for the Matter Standard Vendor ID
                onCommandPayloadMessagePayload.ProtocolId = 0x01; // IM Protocol Messages
                onCommandPayloadMessagePayload.ProtocolOpCode = 0x08; // InvokeRequest

                var onCommandMessageFrame = new MessageFrame(onCommandPayloadMessagePayload);

                onCommandMessageFrame.MessageFlags |= MessageFlags.S;
                onCommandMessageFrame.SecurityFlags = 0x00;
                onCommandMessageFrame.SourceNodeID = BitConverter.ToUInt64(fabric.RootNodeId.ToByteArrayUnsigned());
                onCommandMessageFrame.DestinationNodeId = BitConverter.ToUInt64(peerNodeId.ToByteArrayUnsigned());

                await caseExchange.SendAsync(onCommandMessageFrame);

                var onCommandResultFrame = await caseExchange.WaitForNextMessageAsync();

                await caseExchange.AcknowledgeMessageAsync(onCommandResultFrame.MessageCounter);

                Console.WriteLine("┌────────────────────────┐");
                Console.WriteLine("| Let there be darkness! |");
                Console.WriteLine("└────────────────────────┘");

                caseExchange = caseSession.CreateExchange();

                var offCommandPayload = new MatterTLV();
                offCommandPayload.AddStructure();
                offCommandPayload.AddBool(0, false);
                offCommandPayload.AddBool(1, false);
                offCommandPayload.AddArray(tagNumber: 2); // InvokeRequests

                offCommandPayload.AddStructure();

                offCommandPayload.AddList(tagNumber: 0); // CommandPath

                offCommandPayload.AddUInt16(tagNumber: 0, 0x01); // Endpoint 0x01
                offCommandPayload.AddUInt32(tagNumber: 1, 0x06); // ClusterId 0x06 - OnOff
                offCommandPayload.AddUInt16(tagNumber: 2, 0x00); // 1.5.7 Command Off

                offCommandPayload.EndContainer();

                offCommandPayload.AddStructure(1); // CommandFields
                offCommandPayload.EndContainer(); // Close the CommandFields

                offCommandPayload.EndContainer(); // Close the structure

                offCommandPayload.EndContainer(); // Close the array

                offCommandPayload.AddUInt8(255, 12); // interactionModelRevision

                offCommandPayload.EndContainer(); // Close the structure

                var offCommandPayloadMessagePayload = new MessagePayload(offCommandPayload);

                offCommandPayloadMessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                // Table 14. Protocol IDs for the Matter Standard Vendor ID
                offCommandPayloadMessagePayload.ProtocolId = 0x01; // IM Protocol Messages
                offCommandPayloadMessagePayload.ProtocolOpCode = 0x08; // InvokeRequest

                var offCommandMessageFrame = new MessageFrame(offCommandPayloadMessagePayload);

                offCommandMessageFrame.MessageFlags |= MessageFlags.S;
                offCommandMessageFrame.SecurityFlags = 0x00;
                offCommandMessageFrame.SourceNodeID = BitConverter.ToUInt64(fabric.RootNodeId.ToByteArrayUnsigned());
                offCommandMessageFrame.DestinationNodeId = BitConverter.ToUInt64(peerNodeId.ToByteArrayUnsigned());

                await caseExchange.SendAsync(offCommandMessageFrame);

                var offCommandResultFrame = await caseExchange.WaitForNextMessageAsync();

                await caseExchange.AcknowledgeMessageAsync(offCommandResultFrame.MessageCounter);
            }
            catch (Exception exp)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error: {0}", exp.Message);
            }
        }
    }

    internal class NetworkCommissioner : ICommissioner
    {
        private readonly Fabric _fabric;
        private readonly int _commissionerId;
        //private Thread _commissioningThread;

        public delegate void CommissioningStepEventHandler(object sender, CommissioningStepEventArgs e);
        public event CommissioningStepEventHandler ThresholdReached;

        public NetworkCommissioner(Fabric fabric)
        {
            _fabric = fabric;
            _commissionerId = RandomNumberGenerator.GetInt32(0, 1000000);
        }

        public int Id => _commissionerId;

        public async Task CommissionDeviceAsync(int discriminator)
        {
            ManualResetEvent resetEvent = new ManualResetEvent(false);

            // Run the commissioning in a thread.
            //
            var commissioningThread = new NetworkCommissioningThread(discriminator, resetEvent);

            var commissioningTask = Task.Run(() =>
            {
                commissioningThread.PerformDiscovery(_fabric);
                resetEvent.Set();
            });

            Task.WaitAll([commissioningTask], TimeSpan.FromSeconds(60));

            //// Start the thread, passing the fabric as a parameter.
            ////
            //_commissioningThread = new Thread(new ParameterizedThreadStart(commissioningThread.PerformDiscovery));
            //_commissioningThread.Start(_fabric);
            //_commissioningThread.Join();
        }
    }
}