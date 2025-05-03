using Matter.Core.Fabrics;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
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

        public static X509Certificate GenerateRootCertificate(string fabricName, ulong fabricId, ulong rootCertificateId, AsymmetricCipherKeyPair keyPair)
        {
            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            var rootCertId = new BigInteger("1");

            var rootKeyIdentifier = SHA256.HashData(publicKey.Q.GetEncoded()).AsSpan().Slice(0, 20).ToArray();

            var subjectOids = new List<DerObjectIdentifier>();
            var subjectValues = new List<string>();

            subjectOids.Add(new DerObjectIdentifier("1.3.6.1.4.1.37244.1.4"));
            subjectValues.Add($"{rootCertificateId:X16}");

            X509Name subjectDN = new X509Name(subjectOids, subjectValues);

            var issuerOids = new List<DerObjectIdentifier>();
            var issuerValues = new List<string>();

            issuerOids.Add(new DerObjectIdentifier("1.3.6.1.4.1.37244.1.4"));
            issuerValues.Add($"{rootCertificateId:X16}");

            X509Name issuerDN = new X509Name(issuerOids, issuerValues);

            var certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.SetSerialNumber(rootCertId);
            certificateGenerator.SetPublicKey(publicKey);
            certificateGenerator.SetSubjectDN(subjectDN);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetNotBefore(DateTime.UtcNow.AddYears(-1));
            certificateGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, true, new SubjectKeyIdentifier(rootKeyIdentifier));
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, true, new AuthorityKeyIdentifier(rootKeyIdentifier));




            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", privateKey);

            var rootCertificate = certificateGenerator.Generate(signatureFactory);

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
            var curve = ECNamedCurveTable.GetByName("Secp256r1");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            var secureRandom = new SecureRandom();
            var keyParams = new ECKeyGenerationParameters(domainParams, secureRandom);

            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(keyParams);
            var keyPair = generator.GenerateKeyPair();

            return keyPair;
        }
    }
}
