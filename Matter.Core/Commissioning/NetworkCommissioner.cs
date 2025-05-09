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
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Interop;

namespace Matter.Core.Commissioning
{
    public class NetworkCommissioningThread
    {
        private readonly int _discriminator;
        private readonly ManualResetEvent _resetEvent;
        private readonly List<ulong> _receivedAdvertisments = new();

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

                UnsecureSession session = new UnsecureSession(udpConnection);

                var unsecureExchange = session.CreateExchange();

                Console.WriteLine("┌───────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 6 - Establish PASE |");
                Console.WriteLine("└───────────────────────────────────────┘");

                // Perform the PASE exchange.
                //
                Console.WriteLine("┌───────────────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 6 - Send PBKDFParamRequest |");
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

                Console.WriteLine(responseMessageFrame.MessagePayload.ApplicationPayload.ToString());

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
                var PBKDFParamResponse = responseMessageFrame.MessagePayload.ApplicationPayload;

                PBKDFParamResponse.OpenStructure();

                var initiatorRandomBytes2 = PBKDFParamResponse.GetOctetString(1);
                var responderRandomBytes = PBKDFParamResponse.GetOctetString(2);
                var responderSessionId = PBKDFParamResponse.GetUnsignedInt16(3);

                var peerSessionId = responderSessionId;

                Console.WriteLine("Responder Session Id: {0}", responderSessionId);

                PBKDFParamResponse.OpenStructure(4);

                var iterations = PBKDFParamResponse.GetUnsignedInt16(1);
                var salt = PBKDFParamResponse.GetOctetString(2);

                Console.WriteLine("Iterations: {0}\nSalt Base64: {1}", iterations, Convert.ToBase64String(salt));

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

                var pake2 = pake2MessageFrame.MessagePayload.ApplicationPayload;

                pake2.OpenStructure();

                var Y = pake2.GetOctetString(1);
                var Verifier = pake2.GetOctetString(2);

                Console.WriteLine("Y: {0}", BitConverter.ToString(Y).Replace("-", ""));
                Console.WriteLine("Verifier: {0}", BitConverter.ToString(Verifier).Replace("-", ""));

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

                Console.WriteLine("┌────────────────┐");
                Console.WriteLine("| PASE Complete! |");
                Console.WriteLine("└────────────────┘");

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

                Console.WriteLine("┌───────────────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 11 - Receiving CSRResponse |");
                Console.WriteLine("└───────────────────────────────────────────────┘");

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

                Console.WriteLine("Decoded NOC CSR");
                Console.WriteLine();
                Console.WriteLine(nocPayload);

                nocPayload.OpenStructure();
                var derBytes = nocPayload.GetOctetString(1);

                var certificateRequest = new Pkcs10CertificationRequest(derBytes);

                var peerPublicKey = certificateRequest.GetPublicKey();

                var nocPublicKey = peerPublicKey as ECPublicKeyParameters;
                var nocPublicKeyBytes = nocPublicKey.Q.GetEncoded(false);
                var nocKeyIdentifier = SHA1.HashData(nocPublicKeyBytes).AsSpan().Slice(0, 20).ToArray();

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
                subjectValues.Add($"DEDEDEDE00010001");
                subjectValues.Add($"FAB000000000001D");

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
                certGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
                certGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
                certGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.id_kp_clientAuth, KeyPurposeID.id_kp_serverAuth));
                certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(nocKeyIdentifier));

                // This doesn't seems to work.
                // var authorityKeyIdentifier = fabric.RootCertificate.GetExtension(X509Extensions.AuthorityKeyIdentifier).Value;
                certGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(fabric.RootKeyIdentifier));

                // Create a signature factory for the specified algorithm. Sign the cert with the RootCertificate PrivateyKey
                //
                ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", fabric.KeyPair.Private as ECPrivateKeyParameters);
                var noc = certGenerator.Generate(signatureFactory);

                // Write the PEM out to disk
                //
                //using PemWriter pemWriter = new PemWriter(new StreamWriter("h:\\output.pem"));

                //pemWriter.WriteObject(noc);

                //pemWriter.Writer.Flush();

                //File.WriteAllBytes("h:\\output_noc.cer", noc.GetEncoded());

                noc.CheckValidity();

                Console.WriteLine("NOC Certificate");
                Console.WriteLine(noc);

                Console.WriteLine("───────────────── DER ENCODED CERT ────────────────");
                Console.WriteLine(BitConverter.ToString(noc.GetEncoded()).Replace("-", ""));
                Console.WriteLine("───────────────────────────────────────────────────");
                Console.WriteLine();

                await paseExchange.AcknowledgeMessageAsync(csrResponseMessageFrame.MessageCounter);

                #region AddTrustedRootCertificate

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
                encodedRootCertificate.AddUInt64(20, fabric.RootCertificateId.ToByteArrayUnsigned());
                encodedRootCertificate.EndContainer(); // Close List

                encodedRootCertificate.AddUInt8(7, 1); // public-key-algorithm
                encodedRootCertificate.AddUInt8(8, 1); // elliptic-curve-id

                var rootPublicKey = fabric.RootCertificate.GetPublicKey() as ECPublicKeyParameters;
                var rootPublicKeyBytes = rootPublicKey!.Q.GetEncoded(false);
                encodedRootCertificate.AddOctetString(9, rootPublicKeyBytes); // PublicKey

                Console.WriteLine("Root Certificate PublicKey: {0}", BitConverter.ToString(rootPublicKeyBytes).Replace("-", ""));

                encodedRootCertificate.AddList(10); // Extensions

                encodedRootCertificate.AddStructure(1); // Basic Constraints
                encodedRootCertificate.AddBool(1, true); // is-ca
                encodedRootCertificate.EndContainer(); // Close Basic Constraints

                // 6.5.11.2.Key Usage Extension We want keyCertSign (0x20) and CRLSign (0x40)
                encodedRootCertificate.AddUInt8(2, 0x60);

                encodedRootCertificate.AddOctetString(4, fabric.RootKeyIdentifier); // subject-key-id
                encodedRootCertificate.AddOctetString(5, fabric.RootKeyIdentifier); // authority-key-id

                encodedRootCertificate.EndContainer(); // Close Extensions

                Console.WriteLine(fabric.RootCertificate);

                Console.WriteLine("───────────────── DER ENCODED CERT ────────────────");
                Console.WriteLine(BitConverter.ToString(fabric.RootCertificate.GetEncoded()).Replace("-", ""));
                Console.WriteLine("───────────────────────────────────────────────────");
                Console.WriteLine();

                // Signature. This is an ASN1 EC Signature that is DER encoded.
                // The Matter specification just wants the two parts r & s.
                //
                var signature = fabric.RootCertificate.GetSignature();
                Console.WriteLine("Signature: {0}", BitConverter.ToString(signature));

                // We need to convert this signature into a TLV format.
                //
                AsnDecoder.ReadSequence(signature.AsSpan(), AsnEncodingRules.DER, out var offset, out var length, out _);

                var source = signature.AsSpan().Slice(offset, length).ToArray();

                var r = AsnDecoder.ReadInteger(source, AsnEncodingRules.DER, out var bytesConsumed);
                var s = AsnDecoder.ReadInteger(source.AsSpan().Slice(bytesConsumed), AsnEncodingRules.DER, out bytesConsumed);

                var sig = r.ToByteArray(isUnsigned: true, isBigEndian: true).Concat(s.ToByteArray(isUnsigned: true, isBigEndian: true)).ToArray();

                encodedRootCertificate.AddOctetString(11, sig);

                encodedRootCertificate.EndContainer(); // Close Structure

                Console.WriteLine("───────────────────────────────────────────────────");
                Console.WriteLine("EncodedRootCertificate");
                Console.WriteLine(encodedRootCertificate);
                Console.WriteLine("───────────────────────────────────────────────────");

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
                var encodedNocCertificate = new MatterTLV();
                encodedNocCertificate.AddStructure();

                encodedNocCertificate.AddOctetString(1, noc.SerialNumber.ToByteArrayUnsigned()); // SerialNumber
                encodedNocCertificate.AddUInt8(2, 1); // signature-algorithm

                encodedNocCertificate.AddList(3); // Issuer
                encodedNocCertificate.AddUInt64(20, fabric.RootCertificateId.ToByteArrayUnsigned());
                encodedNocCertificate.EndContainer(); // Close List

                notBefore = new DateTimeOffset(noc.NotBefore).ToEpochTime();
                notAfter = new DateTimeOffset(noc.NotAfter).ToEpochTime();

                encodedNocCertificate.AddUInt32(4, (uint)notBefore); // NotBefore
                encodedNocCertificate.AddUInt32(5, (uint)notAfter); // NotAfter

                encodedNocCertificate.AddList(6); // Subject
                                                  //encodedNocCertificate.AddUTF8String(17, "2"); // NodeId
                                                  //encodedNocCertificate.AddUTF8String(21, "TestFabric"); // FabricId

                var nodeIdBytes = "DEDEDEDE00010001".ToByteArray();
                var nodeId = new BigInteger(nodeIdBytes, false);

                encodedNocCertificate.AddUInt64(17, nodeId.ToByteArrayUnsigned()); // NodeId

                encodedNocCertificate.AddUInt64(21, fabric.FabricId.ToByteArrayUnsigned()); // FabricId
                encodedNocCertificate.EndContainer(); // Close List

                encodedNocCertificate.AddUInt8(7, 1); // public-key-algorithm
                encodedNocCertificate.AddUInt8(8, 1); // elliptic-curve-id

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

                encodedNocCertificate.AddOctetString(4, nocKeyIdentifier); // subject-key-id
                encodedNocCertificate.AddOctetString(5, fabric.RootKeyIdentifier); // authority-key-id

                encodedNocCertificate.EndContainer(); // Close Extensions

                // Signature. This is an ASN1 EC Signature that is DER encoded.
                // The Matter specification just wants the two parts r & s.
                //
                var nocSignature = noc.GetSignature();
                Console.WriteLine("Signature: {0}", BitConverter.ToString(signature));

                // We need to convert this signature into a TLV format.
                //
                AsnDecoder.ReadSequence(nocSignature.AsSpan(), AsnEncodingRules.DER, out offset, out length, out _);

                source = nocSignature.AsSpan().Slice(offset, length).ToArray();

                r = AsnDecoder.ReadInteger(source, AsnEncodingRules.DER, out bytesConsumed);
                s = AsnDecoder.ReadInteger(source.AsSpan().Slice(bytesConsumed), AsnEncodingRules.DER, out bytesConsumed);

                sig = r.ToByteArray(isUnsigned: true, isBigEndian: true).Concat(s.ToByteArray(isUnsigned: true, isBigEndian: true)).ToArray();

                encodedNocCertificate.AddOctetString(11, sig);

                encodedNocCertificate.EndContainer(); // Close Structure

                Console.WriteLine("───────────────────────────────────────────────────");
                Console.WriteLine("Encoded NOC");
                Console.WriteLine(encodedNocCertificate);
                Console.WriteLine("───────────────────────────────────────────────────");

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

                addNocRequest.AddOctetString(0, encodedNocCertificate.GetBytes()); // NOCValue
                addNocRequest.AddOctetString(2, fabric.IPK); // IPKValue
                addNocRequest.AddUInt64(3, 2); // CaseAdminSubject - In this case a NodeId of 2.
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

                #endregion

                // Perform Step 13 of the Commissioning Flow.
                //
                Console.WriteLine("┌──────────────────────────────────────────────────┐");
                Console.WriteLine("| COMMISSIONING STEP 20 - Security Setup With CASE |");
                Console.WriteLine("└──────────────────────────────────────────────────┘");

                // Create a new Exchange
                //
                paseExchange = paseSession.CreateExchange();

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

                // Destination identifier is a composite
                //
                MemoryStream ms = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(ms);
                writer.Write(spake1InitiatorRandomBytes);
                writer.Write(rootPublicKeyBytes);
                writer.Write(fabric.FabricId.ToByteArrayUnsigned());
                writer.Write(nodeId.ToByteArrayUnsigned());

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

                var sigma2MessageFrame = await paseExchange.WaitForNextMessageAsync();

                sigma2MessageFrame.MessagePayload.ApplicationPayload.OpenStructure();

                var sigma2ResponderRandom = sigma2MessageFrame.MessagePayload.ApplicationPayload.GetOctetString(1);
                var sigma2ResponderSessionId = sigma2MessageFrame.MessagePayload.ApplicationPayload.GetUnsignedInt16(2);
                var sigma2ResponderEphPublicKey = sigma2MessageFrame.MessagePayload.ApplicationPayload.GetOctetString(3);
                var sigma2EncryptedPayload = sigma2MessageFrame.MessagePayload.ApplicationPayload.GetOctetString(4);

                // Generate the shared secret.
                //
                var sigmaKeyAgreement = AgreementUtilities.GetBasicAgreement("ECDH");
                sigmaKeyAgreement.Init(ephermeralPrivateKey);

                var curve = ECNamedCurveTable.GetByName("P-256");
                var ecPoint = curve.Curve.DecodePoint(sigma2ResponderEphPublicKey);
                var ephPublicKey = new ECPublicKeyParameters(ecPoint, new ECDomainParameters(curve));

                var sharedSecret = sigmaKeyAgreement.CalculateAgreement(ephPublicKey);

                Console.WriteLine("SharedSecret: {0}", BitConverter.ToString(sharedSecret.ToByteArrayUnsigned()).Replace("-", ""));

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
                hkdf.Init(new HkdfParameters(sharedSecret.ToByteArrayUnsigned(), salt, info));

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

                Console.WriteLine(TBEData2);

                // Build sigma-3-tbsdata
                //
                var sigma3tbs = new MatterTLV();

                sigma3tbs.AddStructure();

                sigma3tbs.AddOctetString(1, fabric.RootCertificate.GetEncoded()); // initiatorNOC
                sigma3tbs.AddOctetString(3, ephermeralPublicKeysBytes); // initiatorEphPubKey
                sigma3tbs.AddOctetString(4, sigma2ResponderEphPublicKey); // responderEphPubKey

                sigma3tbs.EndContainer();

                var sigma3tbsBytes = sigma3tbs.GetBytes();

                Console.WriteLine("sigma3tbsBytes {0}", BitConverter.ToString(sigma3tbsBytes).Replace("-", ""));

                // Sign this tbsData3.
                //
                var signer = SignerUtilities.GetSigner("SHA-1withECDSA");
                signer.Init(true, fabric.KeyPair.Private as ECPrivateKeyParameters);
                signer.BlockUpdate(sigma3tbsBytes, 0, sigma3tbsBytes.Length);
                byte[] sigma3tbsSignature = signer.GenerateSignature();

                var sigma3tbe = new MatterTLV();
                sigma3tbe.AddStructure();
                sigma3tbe.AddOctetString(1, fabric.RootCertificate.GetEncoded());
                sigma3tbe.AddOctetString(3, sigma3tbsSignature);
                sigma3tbe.EndContainer();

                var sigma2Payload = sigma2MessageFrame.MessagePayload.ApplicationPayload;

                Console.WriteLine("sigma1Bytes {0}", BitConverter.ToString(sigma1Payload.GetBytes()).Replace("-", ""));
                Console.WriteLine("sigma2Bytes {0}", BitConverter.ToString(sigma2Payload.GetBytes()).Replace("-", ""));

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
                hkdf.Init(new HkdfParameters(sharedSecret.ToByteArrayUnsigned(), salt, info));

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

                Console.WriteLine(format: "S3 Encrypted: {0}", BitConverter.ToString(encryptedData).Replace("-", ""));

                var sigma3 = new MatterTLV();
                sigma3.AddStructure();
                sigma3.AddOctetString(1, encryptedData); // sigma3EncryptedPayload
                sigma3.EndContainer();

                var sigma3MessagePayload = new MessagePayload(sigma3);

                sigma3MessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                sigma3MessagePayload.ProtocolId = 0x00;
                sigma3MessagePayload.ProtocolOpCode = 0x32; // Sigma3

                var sigma3MessageFrame = new MessageFrame(sigma3MessagePayload);

                sigma3MessageFrame.MessageFlags |= MessageFlags.S;
                sigma3MessageFrame.SecurityFlags = 0x00;
                sigma3MessageFrame.SourceNodeID = 0x00;

                await paseExchange.SendAsync(sigma3MessageFrame);

                var successMessageFrame = await paseExchange.WaitForNextMessageAsync();

                if (MessageFrame.IsStatusReport(successMessageFrame))
                {
                    Console.WriteLine(successMessageFrame.MessagePayload.ApplicationPayload);
                }

                await paseExchange.AcknowledgeMessageAsync(successMessageFrame.MessageCounter);

                if (MessageFrame.IsStatusReport(successMessageFrame))
                {
                    Console.WriteLine(successMessageFrame.MessagePayload.ApplicationPayload);
                }

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