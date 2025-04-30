using Matter.Core.Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System.Numerics;
using System.Security.Cryptography;

namespace Matter.Core.Fabrics
{
    internal class Fabric
    {
        public AsymmetricCipherKeyPair KeyPair { get; private set; }

        public X509Certificate RootCertificate { get; private set; }

        public byte[] IPK { get; private set; }

        public ulong RootNodeId { get; private set; }

        public ushort AdminVendorId { get; private set; }

        public static Fabric CreateNew(string fabricName)
        {
            // TODO Save this Fabric
            //
            var keyPair = CertificateAuthority.GenerateKeyPair();
            var rootCertificate = CertificateAuthority.GenerateRootCertificate(keyPair);

            var random = RandomNumberGenerator.GetBytes(8);
            var rootNodeId = BitConverter.ToUInt64(random);

            return new Fabric()
            {
                RootNodeId = rootNodeId,
                AdminVendorId = 0xFFF1, // Default value from Matter specification 
                KeyPair = keyPair,
                RootCertificate = rootCertificate,
                IPK = RandomNumberGenerator.GetBytes(16),
            };
        }
    }
}
