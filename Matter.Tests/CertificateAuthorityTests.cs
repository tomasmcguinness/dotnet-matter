using Matter.Core;
using Matter.Core.Certificates;
using Org.BouncyCastle.Math;

namespace Matter.Tests;

public class CertificateAuthorityTests
{
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
        var rootCertificateIdBytes = "CACACACA00000001".ToByteArray();
        var rootCertificateId = new BigInteger(rootCertificateIdBytes, false);
        var keypair = CertificateAuthority.GenerateKeyPair();

        var rootCertificate = CertificateAuthority.GenerateRootCertificate(fabricName, fabricId, rootCertificateId, keypair);

        rootCertificate.Verify(keypair.Public);

        var derEncodedCert = rootCertificate.GetEncoded();

        File.WriteAllBytes("h:\\output.cer", derEncodedCert);

        Console.WriteLine(rootCertificate);
    }
}
