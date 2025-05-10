using Matter.Core.Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;
using System.Text;

namespace Matter.Core.Fabrics
{
    internal class Fabric
    {
        public AsymmetricCipherKeyPair KeyPair { get; private set; }

        public BigInteger RootCertificateId { get; private set; }

        public X509Certificate RootCertificate { get; private set; }

        public byte[] IPK { get; private set; }

        public byte[] OperationalIPK { get; private set; }

        public BigInteger RootNodeId { get; private set; }

        public ushort AdminVendorId { get; private set; }

        public byte[] RootKeyIdentifier { get; private set; }
        public BigInteger FabricId { get; private set; }
        public X509Certificate OperationalCertificate { get; private set; }
        public AsymmetricCipherKeyPair OperationalCertificateKeyPair { get; private set; }

        public static Fabric CreateNew(string fabricName)
        {
            var fabricIdBytes = "FAB000000000001D".ToByteArray();
            var fabricId = new BigInteger(fabricIdBytes, false);

            var rootCertificateIdBytes = "CACACACA00000001".ToByteArray();
            var rootCertificateId = new BigInteger(rootCertificateIdBytes, false);
            var rootNodeId = new BigInteger(rootCertificateIdBytes, false);

            var keyPair = CertificateAuthority.GenerateKeyPair();
            var rootCertificate = CertificateAuthority.GenerateRootCertificate(rootCertificateId, keyPair);

            // TODO I'm doing this twice; here and in GenerateRootCertificate()
            var publicKey = rootCertificate.GetPublicKey() as ECPublicKeyParameters;
            var rootKeyIdentifier = SHA1.HashData(publicKey.Q.GetEncoded(false)).AsSpan().Slice(0, 20).ToArray();

            // Also called the EpochKey
            //
            var ipk = RandomNumberGenerator.GetBytes(16);

            byte[] compressedFabricInfo = Encoding.ASCII.GetBytes("CompressedFabric");

            // Generate the CompressedFabricIdentifier using HKDF.
            //
            var keyBytes = publicKey.Q.GetEncoded().AsSpan().Slice(1).ToArray();

            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(keyBytes, fabricIdBytes, compressedFabricInfo));

            var compressedFabricIdentifier = new byte[8];
            hkdf.GenerateBytes(compressedFabricIdentifier, 0, 8);

            // Generate the OperationalGroupKey(OperationalIPK) using HKDF.
            //
            byte[] groupKey = Encoding.ASCII.GetBytes("GroupKey v1.0");
            hkdf.Init(new HkdfParameters(ipk, compressedFabricIdentifier, groupKey));

            var operationalIPK = new byte[16];
            hkdf.GenerateBytes(operationalIPK, 0, 16);

            Console.WriteLine($"Fabric ID: {fabricId}");
            Console.WriteLine($"IPK: {BitConverter.ToString(ipk).Replace("-", "")}");
            Console.WriteLine($"CompressedFabricIdentifier: {BitConverter.ToString(compressedFabricIdentifier).Replace("-", "")}");
            Console.WriteLine($"OperationalIPK: {BitConverter.ToString(operationalIPK).Replace("-", "")}");

            var (noc, nocKeyPair) = GenerateNOC(rootKeyIdentifier);

            return new Fabric()
            {
                FabricId = fabricId,
                RootNodeId = rootNodeId,
                AdminVendorId = 0xFFF1, // Default value from Matter specification 
                KeyPair = keyPair,
                RootCertificateId = rootCertificateId,
                RootCertificate = rootCertificate,
                RootKeyIdentifier = rootKeyIdentifier,
                IPK = ipk,
                OperationalIPK = operationalIPK,
                OperationalCertificate = noc,
                OperationalCertificateKeyPair = nocKeyPair,
            };
        }

        private static (X509Certificate, AsymmetricCipherKeyPair) GenerateNOC(byte[] rootKeyIdentifier)
        {
            var keyPair = CertificateAuthority.GenerateKeyPair();

            var nocPublicKey = keyPair.Public as ECPublicKeyParameters;
            var nocPublicKeyBytes = nocPublicKey.Q.GetEncoded(false);
            var nocKeyIdentifier = SHA1.HashData(nocPublicKeyBytes).AsSpan().Slice(0, 20).ToArray();


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
            subjectValues.Add($"ABABABAB00010001");
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

            certGenerator.SetPublicKey(keyPair.Public as ECPublicKeyParameters);

            // Add the BasicConstraints and SubjectKeyIdentifier extensions
            certGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            certGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
            certGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.id_kp_clientAuth, KeyPurposeID.id_kp_serverAuth));
            certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(nocKeyIdentifier));
            certGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(rootKeyIdentifier));

            // Create a signature factory for the specified algorithm. Sign the cert with the RootCertificate PrivateyKey
            //
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", keyPair.Private as ECPrivateKeyParameters);
            var noc = certGenerator.Generate(signatureFactory);

            return (noc, keyPair);
        }
    }
}
