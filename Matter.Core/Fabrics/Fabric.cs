using Matter.Core.Certificates;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;

namespace Matter.Core.Fabrics
{
    internal class Fabric
    {
        public X509Certificate RootCertificate { get; private set; }

        public byte[] IPK { get; private set; }

        public static Fabric CreateNew(string fabricName)
        {
            // TODO Save this Fabric
            //
            var rootCertificate = CertificateAuthority.GenerateRootCertificate();

            return new Fabric()
            {
                RootCertificate = rootCertificate,
                IPK = RandomNumberGenerator.GetBytes(16),
            };
        }
    }
}
