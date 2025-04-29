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
        var rootCertificate = CertificateAuthority.GenerateRootCertificate();
    }
}
