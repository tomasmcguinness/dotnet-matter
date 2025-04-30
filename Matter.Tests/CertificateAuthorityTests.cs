using Matter.Core.Certificates;

namespace Matter.Tests;

public class CertificateAuthorityTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void GenerateRootCertificate()
    {
        var keypair = CertificateAuthority.GenerateKeyPair();
        var rootCertificate = CertificateAuthority.GenerateRootCertificate(keypair);
    }
}
