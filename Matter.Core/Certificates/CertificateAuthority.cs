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
        public static X509Certificate GenerateRootCertificate(AsymmetricCipherKeyPair keyPair)
        {
            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            var rootCertId = new BigInteger("1");

            var rootKeyIdentifier = SHA256.HashData(publicKey.Q.GetEncoded()).AsSpan().Slice(0, 20).ToArray();

            var certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.SetSerialNumber(rootCertId);
            certificateGenerator.SetPublicKey(publicKey);
            certificateGenerator.SetSubjectDN(new X509Name("CN=RootCA"));
            certificateGenerator.SetIssuerDN(new X509Name("CN=RootCA"));
            certificateGenerator.SetNotBefore(DateTime.UtcNow.AddYears(-1));
            certificateGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, true, new SubjectKeyIdentifier(rootKeyIdentifier));
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, true, new AuthorityKeyIdentifier(rootKeyIdentifier));

            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", privateKey);

            var rootCertificate = certificateGenerator.Generate(signatureFactory);

            return rootCertificate;
        }

        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var curve = ECNamedCurveTable.GetByName("secp256k1");
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
