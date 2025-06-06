using Matter.Core.Fabrics;
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

                await nodeNeedingConnection.Connect(_nodeRegister);
            }
        }
    }
}
