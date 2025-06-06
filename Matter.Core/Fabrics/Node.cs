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

        public async Task Connect(INodeRegister nodeRegister)
        {
            try
            {
                IPAddress? ipAddress = null; //LastKnownIpAddress;
                ushort? port = null; //LastKnownPort;

                var addresses = nodeRegister.GetCommissionedNodeAddresses(Fabric.GetFullNodeName(this));

                if (addresses.Count() == 0)
                {
                    IsConnected = false;
                    return;
                }

                var connection = new UdpConnection(ipAddress!, port!.Value);

                var unsecureSession = new UnsecureSession(connection);

                CASEClient client = new CASEClient(this, this.Fabric, unsecureSession);

                var _secureSession = await client.EstablishSessionAsync();

                this.IsConnected = true;

                Console.WriteLine($"Established secure session to node {this.NodeId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to establish connection to node {this.NodeId}: {ex.Message}");
                this.IsConnected = false;
            }
        }
    }
}