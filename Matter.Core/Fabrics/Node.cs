using Matter.Core.Fabrics;
using Matter.Core.Sessions;
using Org.BouncyCastle.Math;
using System.Net;

namespace Matter.Core
{
    public class Node
    {
        public ISession _secureSession;

        public BigInteger NodeId { get; set; }

        public string NodeName => BitConverter.ToString(NodeId.ToByteArray().Reverse().ToArray()).Replace("-", "");

        public IPAddress? LastKnownIpAddress { get; set; }

        public ushort? LastKnownPort { get; set; }

        public Fabric Fabric { get; set; }

        public bool IsConnected { get; set; }
    }
}