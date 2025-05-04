using Matter.Core.Certificates;

namespace Matter.Tests;

public class CertificateAuthorityTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void GenerateKeyPair()
    {
        var keypair = CertificateAuthority.GenerateKeyPair();
        Console.WriteLine(keypair);
    }

    [Test]
    public void GenerateRootCertificate()
    {
        var fabricName = "TestFabric";
        var fabricId = (ulong)Random.Shared.NextInt64();
        var rootCertificateId = new Org.BouncyCastle.Math.BigInteger("0");// (ulong)Random.Shared.NextInt64();
        var keypair = CertificateAuthority.GenerateKeyPair();

        var rootCertificate = CertificateAuthority.GenerateRootCertificate(fabricName, fabricId, rootCertificateId, keypair);

        rootCertificate.Verify(keypair.Public);

        Console.WriteLine(rootCertificate);
    }
}
