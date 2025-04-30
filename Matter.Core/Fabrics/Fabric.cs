using Matter.Core.Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;

namespace Matter.Core.Fabrics
{
    internal class Fabric
    {
        public AsymmetricCipherKeyPair KeyPair { get; private set; }

        public X509Certificate RootCertificate { get; private set; }

        public byte[] IPK { get; private set; }

        public static Fabric CreateNew(string fabricName)
        {
            // TODO Save this Fabric
            //
            var keyPair = CertificateAuthority.GenerateKeyPair();
            var rootCertificate = CertificateAuthority.GenerateRootCertificate(keyPair);

            return new Fabric()
            {
                KeyPair = keyPair,
                RootCertificate = rootCertificate,
                IPK = RandomNumberGenerator.GetBytes(16),
            };
        }
    }
}
