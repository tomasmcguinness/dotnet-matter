using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Matter.Core.Cryptography
{
    internal class CryptographyMethods
    {
        public static BigInteger Crypto_PAKEValues_Initiator(uint passcode, ushort iterations, byte[] salt)
        {
            // https://datatracker.ietf.org/doc/rfc9383/
            //
            var GROUP_SIZE_BYTES = 32;
            var CRYPTO_W_SIZE_BYTES = GROUP_SIZE_BYTES + 8;
            var CRYPTO_W_SIZE_BITS = CRYPTO_W_SIZE_BYTES * 8;

            var passcodeBytes = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(passcodeBytes, passcode);

            var pbkdf = Rfc2898DeriveBytes.Pbkdf2(passcodeBytes, salt, iterations, HashAlgorithmName.SHA256, 2 * CRYPTO_W_SIZE_BITS);

            var w0s = new BigInteger(pbkdf.AsSpan().Slice(0, CRYPTO_W_SIZE_BYTES));
            var w1s = new BigInteger(pbkdf.AsSpan().Slice(CRYPTO_W_SIZE_BYTES, CRYPTO_W_SIZE_BYTES));

            var p = new BigInteger(Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"), isUnsigned: true, isBigEndian: true);
            var n = new BigInteger(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"), isUnsigned: true, isBigEndian: true);

            var M = new BigInteger(Convert.FromHexString("02886E2F97ACE46E55BA9DD7242579F2993B64E16EF3DCAB95AFD497333D8FA12F"), isUnsigned: true, isBigEndian: true);
            var N = new BigInteger(Convert.FromHexString("03D8BBD6C639C62937B04D997F38C3770719C629D7014D49A24B4F98BAA1292B49"), isUnsigned: true, isBigEndian: true);

            var G = new BigInteger(Convert.FromHexString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"), isUnsigned: true, isBigEndian: true);

            var w0 = w0s % p;
            var w1 = w1s % p;

            var x = new BigInteger(RandomNumberGenerator.GetBytes(GROUP_SIZE_BYTES), true, true);

            var X = BigInteger.Add(BigInteger.Multiply(x, G), BigInteger.Multiply(w0, M));

            return X;
        }
    }
}
