using Matter.Core.Certificates;

namespace Matter.Core.Fabrics
{
    internal class Fabric
    {
        public static Fabric CreateNew()
        {
            var rootCertificate = CertificateAuthority.GenerateRootCertificate();
            return new Fabric();
        }
    }
}
