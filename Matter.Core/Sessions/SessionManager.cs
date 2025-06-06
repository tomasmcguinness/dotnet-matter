using Matter.Core.Fabrics;
using System.Net;
using System.Threading.Channels;

namespace Matter.Core.Sessions
{
    public class SessionManager : ISessionManager
    {
        private Dictionary<UdpConnection, Node> _connections = new();
        private Dictionary<Node, ISession> _secureSessions = new();
        private Channel<Node> _connectionsQueue = Channel.CreateUnbounded<Node>();
        private readonly INodeRegister _nodeRegister;

        public SessionManager(INodeRegister nodeRegister)
        {
            _nodeRegister = nodeRegister ?? throw new ArgumentNullException(nameof(nodeRegister));
        }

        public ISession GetSecureSession(Node node)
        {
            return _secureSessions[node];
        }

        public async Task Start(Fabric fabric)
        {
            foreach (var node in fabric.Nodes)
            {
                await _connectionsQueue.Writer.WriteAsync(node);
            }

            while (true)
            {
                Console.WriteLine($"Waiting for a node that we need connect to");

                var nodeNeedingConnection = await _connectionsQueue.Reader.ReadAsync();
                await EstablishSecureSession(nodeNeedingConnection);
            }
        }

        private async Task EstablishSecureSession(Node node)
        {
            Console.WriteLine($"Attemting to connect to Node {node.NodeId}");

            try
            {
                IPAddress? ipAddress = node.LastKnownIpAddress;
                ushort? port = node.LastKnownPort;

                if (ipAddress is null)
                {
                    var addresses = _nodeRegister.GetCommissionedNodeAddresses(node.Fabric.GetFullNodeName(node));
                    throw new Exception($"Node {node.NodeId} does not have a known IP address.");
                }

                var connection = new UdpConnection(ipAddress!, port!.Value);

                _connections[connection] = node;

                connection.Open();

                var unsecureSession = new UnsecureSession(connection);

                CASEClient client = new CASEClient(node, node.Fabric, unsecureSession);

                var _secureSession = await client.EstablishSessionAsync();

                _secureSessions[node] = _secureSession;

                node.IsConnected = true;

                Console.WriteLine($"Established secure session to node {node.NodeId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to establish connection to node {node.NodeId}: {ex.Message}");
                node.IsConnected = false;

                await Task.Delay(5000); // Wait a bit before trying to reconnect
                await _connectionsQueue.Writer.WriteAsync(node);
            }
        }

        //private void Connection_ConnectionClosed(object? sender, EventArgs e)
        //{
        //    Console.WriteLine($"A connection was closed. Cleanup and try again.");

        //    // A connection failed.
        //    //
        //    var closedConnection = sender as UdpConnection;

        //    if (closedConnection is null)
        //    {
        //        return;
        //    }

        //    var impactedNode = _connections[closedConnection];

        //    impactedNode.LastKnownPort = null;
        //    impactedNode.LastKnownIpAddress = null;

        //    impactedNode.IsConnected = false;

        //    Thread.Sleep(5000); // Wait a bit before trying to reconnect

        //    var result = _connectionsQueue.Writer.TryWrite(impactedNode);
        //}
    }
}
