using Matter.Core.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using System.Text;

namespace Matter.Tests
{
    public class Spake2PlusTests
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void TestVectors()
        {
            // This test uses some of the Test Vectors from the Spake2+ RFC (https://datatracker.ietf.org/doc/html/draft-bar-cfrg-spake2plus-02#appendix-B)
            //
            X9ECParameters ecP = ECNamedCurveTable.GetByName("Secp256r1");

            var M = ecP.Curve.DecodePoint(Convert.FromHexString("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"));
            var N = ecP.Curve.DecodePoint(Convert.FromHexString("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"));

            BigInteger w0 = new BigInteger(1, Convert.FromHexString("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c"), true);
            BigInteger w1 = new BigInteger(1, Convert.FromHexString("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512"), true);

            //x < - [0, p)
            BigInteger x = new BigInteger(1, Convert.FromHexString("8b0f3f383905cf3a3bb955ef8fb62e24849dd349a05ca79aafb18041d30cbdb6"), true);

            // G is generator (P)
            // X = x*P + w0*M
            //
            var X = ecP.G.Multiply(x).Add(M.Multiply(w0)).Normalize();

            var Xs = BitConverter.ToString(X.GetEncoded(false)).Replace("-", "");

            // Check that X is generated as expected!
            //
            Assert.That(Xs, Is.EqualTo("04AF09987A593D3BAC8694B123839422C3CC87E37D6B41C1D630F000DD64980E537AE704BCEDE04EA3BEC9B7475B32FA2CA3B684BE14D11645E38EA6609EB39E7E"));

            //y < - [0, p)
            BigInteger y = new BigInteger(1, Convert.FromHexString("2e0895b0e763d6d5a9564433e64ac3cac74ff897f6c3445247ba1bab40082a91"), true);

            //Y = y * P + w0 * N
            var Y = ecP.G.Multiply(y).Add(N.Multiply(w0)).Normalize();

            var Ys = BitConverter.ToString(Y.GetEncoded(false)).Replace("-", "");

            Assert.That(Ys, Is.EqualTo("04417592620AEBF9FD203616BBB9F121B730C258B286F890C5F19FEA833A9C900CBE9057BC549A3E19975BE9927F0E7614F08D1F0A108EEDE5FD7EB5624584A4F4"));

            if (!Y.IsValid())
            {
                throw new InvalidOperationException("pC is not on the curve");
            }

            var yNwo = Y.Add(N.Multiply(w0).Negate());

            //Z = h * x * (Y - w0 * N)
            var Z = yNwo.Multiply(x);

            //V = h * w1 * (Y - w0 * N)
            var V = yNwo.Multiply(w1);

            var Zs = BitConverter.ToString(Z.GetEncoded(false)).Replace("-", "");
            Assert.That(Zs, Is.EqualTo("0471A35282D2026F36BF3CEB38FCF87E3112A4452F46E9F7B47FD769CFB570145B62589C76B7AA1EB6080A832E5332C36898426912E29C40EF9E9C742EEE82BF30"));

            var Vs = BitConverter.ToString(V.GetEncoded(false)).Replace("-", "");
            Assert.That(Vs, Is.EqualTo("046718981BF15BC4DB538FC1F1C1D058CB0EECECF1DBE1B1EA08A4E25275D382E82B348C8131D8ED669D169C2E03A858DB7CF6CA2853A4071251A39FBE8CFC39BC"));
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}