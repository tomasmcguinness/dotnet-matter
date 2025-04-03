using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Matter.Core.Cryptography
{
    internal class CryptographyMethods
    {
        public static Org.BouncyCastle.Math.EC.ECPoint Crypto_PAKEValues_Initiator(uint passcode, ushort iterations, byte[] salt)
        {
            // https://datatracker.ietf.org/doc/rfc9383/
            //
            var GROUP_SIZE_BYTES = 32;
            var CRYPTO_W_SIZE_BYTES = GROUP_SIZE_BYTES + 8;
            var CRYPTO_W_SIZE_BITS = CRYPTO_W_SIZE_BYTES * 8;

            var passcodeBytes = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(passcodeBytes, passcode);

            X9ECParameters ecP = ECNamedCurveTable.GetByName("Secp256r1");

            if (ecP == null)
                throw new Exception("unknown curve name: Secp256r1");

            var domainParameters = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());

            var pbkdf = Rfc2898DeriveBytes.Pbkdf2(passcodeBytes, salt, iterations, HashAlgorithmName.SHA256, 2 * CRYPTO_W_SIZE_BYTES);

            Console.WriteLine("PBKDF2: {0}", Convert.ToBase64String(pbkdf));

            var w0s = new BigInteger(pbkdf.AsSpan().Slice(0, CRYPTO_W_SIZE_BYTES).ToArray(), true);
            var w1s = new BigInteger(pbkdf.AsSpan().Slice(CRYPTO_W_SIZE_BYTES, CRYPTO_W_SIZE_BYTES).ToArray(), true);

            //var p = new BigInteger(Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"), isUnsigned: true, isBigEndian: true);
            //var n = new BigInteger(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"), isUnsigned: true, isBigEndian: true);
            //ecP.G.g

            var M = ecP.Curve.DecodePoint(Convert.FromHexString("02886E2F97ACE46E55BA9DD7242579F2993B64E16EF3DCAB95AFD497333D8FA12F"));

            //var M = new ECPoint(Convert.FromHexString("02886E2F97ACE46E55BA9DD7242579F2993B64E16EF3DCAB95AFD497333D8FA12F"));
            //var N = new BigInteger(Convert.FromHexString("03D8BBD6C639C62937B04D997F38C3770719C629D7014D49A24B4F98BAA1292B49"), isUnsigned: true, isBigEndian: true);

            //var G = new BigInteger(Convert.FromHexString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"), isUnsigned: true, isBigEndian: true);

            //ECPoint ecPoint = new ECPoint();
            //ecPoint.X = new BigInteger(Convert.FromHexString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"), isUnsigned: true, isBigEndian: true).ToByteArray();
            //ecPoint.Y = new BigInteger(Convert.FromHexString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"), isUnsigned: true, isBigEndian: true).ToByteArray();

            var w0 = w0s.Mod(ecP.N);
            var w1 = w1s.Mod(ecP.N);

            BigInteger x = new BigInteger(RandomNumberGenerator.GetBytes(GROUP_SIZE_BYTES), true);

            while (x.CompareTo(ecP.N.Subtract(new BigInteger("1"))) > 0)
            {
                x = new BigInteger(RandomNumberGenerator.GetBytes(GROUP_SIZE_BYTES), true);
            }

            var X = ecP.G.Multiply(x).Add(M.Multiply(w0));

            return X;

            //return new BigInteger("1");
        }
    }
}
