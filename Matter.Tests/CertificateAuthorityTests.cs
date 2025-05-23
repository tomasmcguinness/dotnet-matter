﻿using Matter.Core;
using Matter.Core.Certificates;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

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

        var rootCertificate = CertificateAuthority.GenerateRootCertificate(rootCertificateId, keypair);

        rootCertificate.Verify(keypair.Public);

        var derEncodedCert = rootCertificate.GetEncoded();

        using PemWriter pemWriter = new PemWriter(new StreamWriter("h:\\output.pem"));

        pemWriter.WriteObject(rootCertificate);

        pemWriter.Writer.Flush();

        File.WriteAllBytes("h:\\output.cer", derEncodedCert);

        Console.WriteLine(rootCertificate);
    }

    [Test]
    public void GenerateCertificate()
    {
        TextReader publicKeyReader = new StringReader("-----BEGIN CERTIFICATE-----\r\nMIIBnTCCAUOgAwIBAgIIWeqmMpR/VBwwCgYIKoZIzj0EAwIwIjEgMB4GCisGAQQB\r\ngqJ8AQQMEENBQ0FDQUNBMDAwMDAwMDEwHhcNMjAxMDE1MTQyMzQzWhcNNDAxMDE1\r\nMTQyMzQyWjAiMSAwHgYKKwYBBAGConwBBAwQQ0FDQUNBQ0EwMDAwMDAwMTBZMBMG\r\nByqGSM49AgEGCCqGSM49AwEHA0IABBNTo7PvHacIxJCASAFOQH1ZkM4ivE6zPppa\r\nyyWoVgPrptzYITZmpORPWsoT63Z/r6fc3dwzQR+CowtUPdHSS6ijYzBhMA8GA1Ud\r\nEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQTr4GrNzdLLtKp\r\nZJsSt6OkKH4VHTAfBgNVHSMEGDAWgBQTr4GrNzdLLtKpZJsSt6OkKH4VHTAKBggq\r\nhkjOPQQDAgNIADBFAiBFgWRGbI8ZWrwKu3xstaJ6g/QdN/jVO+7FIKvSoNoFCQIh\r\nALinwlwELjDPZNww/jNOEgAZZk5RUEkTT1eBI4RE/HUx\r\n-----END CERTIFICATE-----");
        PemReader publicPemReader = new PemReader(publicKeyReader);
        var exampleRootCertificate = publicPemReader.ReadObject() as X509Certificate;

        Assert.That(exampleRootCertificate.Version, Is.EqualTo(3));

        Console.WriteLine(BitConverter.ToString(exampleRootCertificate.GetEncoded()).Replace("-", ""));

        var fabricName = "TestFabric";
        var fabricId = (ulong)Random.Shared.NextInt64();
        var rootCertificateIdBytes = "CACACACA00000001".ToByteArray();
        var rootCertificateId = new BigInteger(rootCertificateIdBytes, false);

        var keypair = CertificateAuthority.GenerateKeyPair();

        var rootCertificate = CertificateAuthority.GenerateRootCertificate(rootCertificateId, keypair);

        Console.WriteLine(BitConverter.ToString(rootCertificate.GetEncoded()).Replace("-", ""));
    }

    [Test]
    public void NOC()
    {
        TextReader publicKeyReader = new StringReader($"-----BEGIN CERTIFICATE-----" +
"MIIB4DCCAYagAwIBAgIIPvz /FwK5oXowCgYIKoZIzj0EAwIwIjEgMB4GCisGAQQB" +
"gqJ8AQMMEENBQ0FDQUNBMDAwMDAwMDMwHhcNMjAxMDE1MTQyMzQzWhcNNDAxMDE1" +
"MTQyMzQyWjBEMSAwHgYKKwYBBAGConwBAQwQREVERURFREUwMDAxMDAwMTEgMB4G" +
"CisGAQQBgqJ8AQUMEEZBQjAwMDAwMDAwMDAwMUQwWTATBgcqhkjOPQIBBggqhkjO" +
"PQMBBwNCAASaKiFvs53WtvohG4NciePmr7ZsFPdYMZVPn/T3o/ARLIoNjq8pxlMp" +
"TUju4HCKAyzKOTk8OntG8YGuoHj+rYODo4GDMIGAMAwGA1UdEwEB/wQCMAAwDgYD" +
"VR0PAQH/BAQDAgeAMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAd" +
"BgNVHQ4EFgQUn1Wia35DA+YIg+kTv5T0+14qYWEwHwYDVR0jBBgwFoAUU1LXBZ6c" +
"FaUIkGhihkgBop8fQdMwCgYIKoZIzj0EAwIDSAAwRQIgeVXCAmMLS6TVkSUmMi/f" +
"KPie3+WvnA5XK9ihSqq7TRICIQC4PKF8ewX7Fkt315xSlhMxa8/ReJXksqTyQEuY" +
"FzJxWQ==" +
"-----END CERTIFICATE-----");

        PemReader publicPemReader = new PemReader(publicKeyReader);
        var exampleRootCertificate = publicPemReader.ReadObject() as X509Certificate;
        Assert.That(exampleRootCertificate.Version, Is.EqualTo(3));

        Console.WriteLine(BitConverter.ToString(exampleRootCertificate.GetEncoded()).Replace("-", ""));
    }
}
