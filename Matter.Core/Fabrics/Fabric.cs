using Matter.Core.Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
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

        public static Fabric CreateNew(string fabricName)
        {
            var rootNodeId = (ulong)0;

            var fabricIdBytes = "FAB000000000001D".ToByteArray();
            var fabricId = new BigInteger(fabricIdBytes, false);

            var rootCertificateIdBytes = "CACACACA00000001".ToByteArray();
            var rootCertificateId = new BigInteger(rootCertificateIdBytes, false);

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

            return new Fabric()
            {
                FabricId = fabricId,
                //RootNodeId = rootNodeId,
                AdminVendorId = 0xFFF1, // Default value from Matter specification 
                KeyPair = keyPair,
                RootCertificateId = rootCertificateId,
                RootCertificate = rootCertificate,
                RootKeyIdentifier = rootKeyIdentifier,
                IPK = ipk,
                OperationalIPK = operationalIPK
            };
        }
    }
}
