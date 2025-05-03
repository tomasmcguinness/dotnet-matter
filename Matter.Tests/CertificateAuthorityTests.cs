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
        var fabricName = "TestFabric";
        var fabricId = (ulong)Random.Shared.NextInt64();
        var rootCertificateId = (ulong)Random.Shared.NextInt64();
        var keypair = CertificateAuthority.GenerateKeyPair();

        var rootCertificate = CertificateAuthority.GenerateRootCertificate(fabricName, fabricId, rootCertificateId, keypair);
    }
}
