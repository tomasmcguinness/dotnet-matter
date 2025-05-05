using Matter.Core.Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;

namespace Matter.Core.Fabrics
{
    internal class Fabric
    {
        public AsymmetricCipherKeyPair KeyPair { get; private set; }

        public BigInteger RootCertificateId { get; private set; }

        public X509Certificate RootCertificate { get; private set; }

        public byte[] IPK { get; private set; }

        public ulong RootNodeId { get; private set; }

        public ushort AdminVendorId { get; private set; }

        public byte[] RootKeyIdentifier { get; private set; }

        public static Fabric CreateNew(string fabricName)
        {
            var fabricId = (ulong)0;
            var rootNodeId = (ulong)0;

            var rootCertificateIdBytes = "CACACACA00000001".ToByteArray();
            var rootCertificateId = new BigInteger(rootCertificateIdBytes, false);

            var keyPair = CertificateAuthority.GenerateKeyPair();
            var rootCertificate = CertificateAuthority.GenerateRootCertificate(fabricName, fabricId, rootCertificateId, keyPair);

            // TODO I'm doing this twice; here and in GenerateRootCertificate()
            var publicKey = rootCertificate.GetPublicKey() as ECPublicKeyParameters;
            var rootKeyIdentifier = SHA1.HashData(publicKey.Q.GetEncoded(false)).AsSpan().Slice(0, 20).ToArray();

            return new Fabric()
            {
                RootNodeId = rootNodeId,
                AdminVendorId = 0xFFF1, // Default value from Matter specification 
                KeyPair = keyPair,
                RootCertificateId = rootCertificateId,
                RootCertificate = rootCertificate,
                RootKeyIdentifier = rootKeyIdentifier,
                IPK = RandomNumberGenerator.GetBytes(16),
            };
        }
    }
}
