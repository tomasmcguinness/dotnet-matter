using Matter.Core.Fabrics;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;

namespace Matter.Core.Certificates
{
    public class CertificateAuthority
    {
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static X509Certificate GenerateRootCertificate(string fabricName, ulong fabricId, BigInteger rootCertificateId, AsymmetricCipherKeyPair keyPair)
        {
            //var privateKey = keyPair.Private as ECPrivateKeyParameters;
            //var publicKey = keyPair.Public as ECPublicKeyParameters;

            ////var rootCertId = new BigInteger("1");
            //var rootCertId = new BigInteger("6479173750095827996");

            //var rootKeyIdentifier = SHA256.HashData(publicKey.Q.GetEncoded(false)).AsSpan().Slice(0, 20).ToArray();

            //var subjectOids = new List<DerObjectIdentifier>();
            //var subjectValues = new List<string>();

            //subjectOids.Add(new DerObjectIdentifier("1.3.6.1.4.1.37244.1.4"));
            //subjectValues.Add($"{rootCertificateId:X2}");

            //X509Name subjectDN = new X509Name(subjectOids, subjectValues);

            //var issuerOids = new List<DerObjectIdentifier>();
            //var issuerValues = new List<string>();

            //issuerOids.Add(new DerObjectIdentifier("1.3.6.1.4.1.37244.1.4"));
            //issuerValues.Add($"{rootCertificateId:X2}");

            //X509Name issuerDN = new X509Name(issuerOids, issuerValues);

            //var certificateGenerator = new X509V3CertificateGenerator();
            //certificateGenerator.SetSerialNumber(rootCertId);
            //certificateGenerator.SetPublicKey(publicKey);
            //certificateGenerator.SetSubjectDN(subjectDN);
            //certificateGenerator.SetIssuerDN(issuerDN);
            //certificateGenerator.SetNotBefore(DateTime.UtcNow.AddYears(-1));
            //certificateGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            //certificateGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            //certificateGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            //certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(rootKeyIdentifier));
            //certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(rootKeyIdentifier));

            //ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", privateKey);

            //var rootCertificate = certificateGenerator.Generate(signatureFactory);

            //return rootCertificate;




            TextReader publicKeyReader = new StringReader("-----BEGIN CERTIFICATE-----\r\nMIIBnTCCAUOgAwIBAgIIWeqmMpR/VBwwCgYIKoZIzj0EAwIwIjEgMB4GCisGAQQB\r\ngqJ8AQQMEENBQ0FDQUNBMDAwMDAwMDEwHhcNMjAxMDE1MTQyMzQzWhcNNDAxMDE1\r\nMTQyMzQyWjAiMSAwHgYKKwYBBAGConwBBAwQQ0FDQUNBQ0EwMDAwMDAwMTBZMBMG\r\nByqGSM49AgEGCCqGSM49AwEHA0IABBNTo7PvHacIxJCASAFOQH1ZkM4ivE6zPppa\r\nyyWoVgPrptzYITZmpORPWsoT63Z/r6fc3dwzQR+CowtUPdHSS6ijYzBhMA8GA1Ud\r\nEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQTr4GrNzdLLtKp\r\nZJsSt6OkKH4VHTAfBgNVHSMEGDAWgBQTr4GrNzdLLtKpZJsSt6OkKH4VHTAKBggq\r\nhkjOPQQDAgNIADBFAiBFgWRGbI8ZWrwKu3xstaJ6g/QdN/jVO+7FIKvSoNoFCQIh\r\nALinwlwELjDPZNww/jNOEgAZZk5RUEkTT1eBI4RE/HUx\r\n-----END CERTIFICATE-----");
            PemReader publicPemReader = new PemReader(publicKeyReader);
            var rootCertificate = publicPemReader.ReadObject() as X509Certificate;


            return rootCertificate;



            //this.RCAC = Math.Max(1, (ulong)Random.Shared.NextInt64());
            //var commonName = fabricName;//.Truncate(64);
            //this.IssuerCommonName = CommonName;
            //EpochKey = ipk;
            //X500DistinguishedNameBuilder builder = new X500DistinguishedNameBuilder();
            //builder.Add("2.5.4.3", fabricName, UniversalTagNumber.UTF8String);
            //builder.Add("1.3.6.1.4.1.37244.1.4", $"{rootCertificateId:X16}", UniversalTagNumber.UTF8String);
            //builder.Add("1.3.6.1.4.1.37244.1.5", $"{fabricId:X16}", UniversalTagNumber.UTF8String);

            //ECDsa privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            //CertificateRequest req = new CertificateRequest(builder.Build(), privateKey, HashAlgorithmName.SHA256);

            //req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            //req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

            //X509SubjectKeyIdentifierExtension subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(SHA1.HashData(new BigIntegerPoint(privateKey.ExportParameters(false).Q).ToBytes(false)), false);
            //req.CertificateExtensions.Add(subjectKeyIdentifier);
            //req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subjectKeyIdentifier));

            //return req.CreateSelfSigned(DateTime.Now.Subtract(TimeSpan.FromSeconds(30)), DateTime.Now.AddYears(10));
        }

        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            TextReader publicKeyReader = new StringReader("-----BEGIN CERTIFICATE-----\r\nMIIBnTCCAUOgAwIBAgIIWeqmMpR/VBwwCgYIKoZIzj0EAwIwIjEgMB4GCisGAQQB\r\ngqJ8AQQMEENBQ0FDQUNBMDAwMDAwMDEwHhcNMjAxMDE1MTQyMzQzWhcNNDAxMDE1\r\nMTQyMzQyWjAiMSAwHgYKKwYBBAGConwBBAwQQ0FDQUNBQ0EwMDAwMDAwMTBZMBMG\r\nByqGSM49AgEGCCqGSM49AwEHA0IABBNTo7PvHacIxJCASAFOQH1ZkM4ivE6zPppa\r\nyyWoVgPrptzYITZmpORPWsoT63Z/r6fc3dwzQR+CowtUPdHSS6ijYzBhMA8GA1Ud\r\nEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQTr4GrNzdLLtKp\r\nZJsSt6OkKH4VHTAfBgNVHSMEGDAWgBQTr4GrNzdLLtKpZJsSt6OkKH4VHTAKBggq\r\nhkjOPQQDAgNIADBFAiBFgWRGbI8ZWrwKu3xstaJ6g/QdN/jVO+7FIKvSoNoFCQIh\r\nALinwlwELjDPZNww/jNOEgAZZk5RUEkTT1eBI4RE/HUx\r\n-----END CERTIFICATE-----");
            PemReader publicPemReader = new PemReader(publicKeyReader);
            var publicKey = publicPemReader.ReadObject() as X509Certificate; ;// as ECPublicKeyParameters;

            TextReader sr = new StringReader("-----BEGIN EC PRIVATE KEY-----\r\nMHcCAQEEIH1zW+/pFqHAygL4ypiB5CZjqq+aucQzsom+JnAQdXQaoAoGCCqGSM49\r\nAwEHoUQDQgAEE1Ojs+8dpwjEkIBIAU5AfVmQziK8TrM+mlrLJahWA+um3NghNmak\r\n5E9ayhPrdn+vp9zd3DNBH4KjC1Q90dJLqA==\r\n-----END EC PRIVATE KEY-----");
            PemReader pemReader = new PemReader(sr);
            var privateKey = pemReader.ReadObject(); // as ECPrivateKeyParameters;

            // return new AsymmetricCipherKeyPair(publicKey as AsymmetricKeyParameter, privateKey as AsymmetricKeyParameter);

            //var curve = ECNamedCurveTable.GetByName("Secp256r1");
            //var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            //var secureRandom = new SecureRandom();
            //var keyParams = new ECKeyGenerationParameters(domainParams, secureRandom);

            //var generator = new ECKeyPairGenerator("ECDSA");
            //generator.Init(keyParams);
            //var keyPair = generator.GenerateKeyPair();

            //return keyPair;

            return null;
        }
    }
}
