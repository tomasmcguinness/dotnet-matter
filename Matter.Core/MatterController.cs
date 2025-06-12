using mDNS.Core;
using Matter.Core.Commissioning;
using Matter.Core.Fabrics;
using Microsoft.Extensions.Logging.Abstractions;
using Matter.Core.Sessions;
using Org.BouncyCastle.Math;

namespace Matter.Core
{
    public class MatterController : IMatterController
    {
        private readonly FabricManager _fabricManager;
        private readonly mDNSService _mDNSService;
        private readonly ISessionManager _sessionManager;
        private readonly INodeRegister _nodeRegister;

        private Fabric? _fabric;
        private Dictionary<int, ICommissioner> _commissioners;

        public event IMatterController.ReconnectedToNode ReconnectedToNodeEvent;
        public event IMatterController.MatterNodeAddedToFabric MatterNodeAddedToFabricEvent;

        public MatterController(IFabricStorageProvider fabricStorageProvider)
        {
            _fabricManager = new FabricManager(fabricStorageProvider);
            _commissioners = new Dictionary<int, ICommissioner>();
            _nodeRegister = new NodeRegister();
            _sessionManager = new SessionManager(_nodeRegister);
            _mDNSService = new mDNSService(new NullLogger<mDNSService>());
        }

        public Task<ICommissioner> CreateCommissionerAsync()
        {
            if (_fabric == null)
            {
                throw new InvalidOperationException($"Fabric not initialized. Call {nameof(InitAsync)}() first.");
            }

            ICommissioner commissioner = new NetworkCommissioner(_fabric);

            _commissioners.Add(commissioner.Id, commissioner);

            return Task.FromResult(commissioner);
        }

        public async Task InitAsync()
        {
            // Start the mDNS service to discover nodes.
            //
            _mDNSService.ServiceDiscovered += (object sender, ServiceDetails args) =>
            {
                if (args.Name.Contains("_matter._tcp.local"))
                {
                    _nodeRegister.AddCommissionedNode(args.Name.Replace("_matter._tcp.local", ""), args.Addresses);
                }
            };

            _fabric = await _fabricManager.GetAsync("Test");
            _fabric.NodeAdded += OnNodeAddedToFabric;
        }

        public async Task RunAsync()
        {
            if (_fabric == null)
            {
                throw new InvalidOperationException($"Fabric not initialized. Call {nameof(InitAsync)}() first.");
            }

            // Start the mDNS service to discover commissionable and commissioned nodes.
            //
            _mDNSService.Perform(new ServiceDiscovery("_matter._tcp.local.", "_matterc._tcp.local."));

            // Reconnect to the nodes we have already commissioned.
            //
            await _sessionManager.Start(_fabric!);
        }

        private void OnNodeAddedToFabric(object sender, NodeAddedToFabricEventArgs args)
        {
            MatterNodeAddedToFabricEvent?.Invoke(this, new Events.MatterNodeAddedToFabricEventArgs()
            {

            });
        }

        public Task<IEnumerable<Node>> GetNodesAsync()
        {
            return Task.FromResult(_fabric.Nodes.AsEnumerable());
        }

        public Task<Node> GetNodeAsync(BigInteger nodeId)
        {
            return Task.FromResult(_fabric.Nodes.First(x => x.NodeId.ToString() == nodeId.ToString()));
        }
    }
}
