using Matter.Core.Certificates;
using Org.BouncyCastle.X509;

namespace Matter.Core.Fabrics
{
    internal class Fabric
    {
        public X509Certificate RootCertificate { get; private set; }

        public static Fabric CreateNew(string fabricName)
        {
            // TODO Save this Fabric
            //
            var rootCertificate = CertificateAuthority.GenerateRootCertificate();

            return new Fabric()
            {
                RootCertificate = rootCertificate
            };
        }
    }
}
