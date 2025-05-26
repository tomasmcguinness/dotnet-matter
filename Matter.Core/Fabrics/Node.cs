using Matter.Core.Sessions;
using Org.BouncyCastle.Math;
using System.Net;

namespace Matter.Core.Fabrics
{
    public class Node
    {
        public ISession _secureSession;

        public BigInteger NodeId { get; set; }

        public string NodeName => BitConverter.ToString(NodeId.ToByteArray().Reverse().ToArray()).Replace("-", "");

        public IPAddress LastKnownIpAddress { get; set; }

        public ushort LastKnownPort { get; set; }

        public Fabric Fabric { get; set; }

        public bool IsConnected { get; set; }

        internal async Task Connect()
        {
            // This is an existing node.
            //
            var connection = new UdpConnection(LastKnownIpAddress, LastKnownPort);

            var unsecureSession = new UnsecureSession(connection, 0);

            CASEClient client = new CASEClient(this, Fabric, unsecureSession);

            _secureSession = await client.EstablishSessionAsync();
        }
    }
}