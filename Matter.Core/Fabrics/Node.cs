using Org.BouncyCastle.Math;
using System.Net;

namespace Matter.Core.Fabrics
{
    public class Node
    {
        public BigInteger NodeId { get; set; }

        public string NodeName => BitConverter.ToString(NodeId.ToByteArray().Reverse().ToArray()).Replace("-", "");

        public IPAddress LastKnownIpAddress { get; set; }

        public ushort LastKnownPort { get; set; }

        internal void Connect()
        {
            // This is an existing node.
            //
        }
    }
}