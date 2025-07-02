using Makaretu.Dns;
using Matter.Core.Commissioning;
using Matter.Core.Fabrics;
using Matter.Core.Sessions;
using Org.BouncyCastle.Math;

namespace Matter.Core
{
    public class MatterController : IMatterController
    {
        private readonly FabricManager _fabricManager;
        //private readonly mDNSService _mDNSService;
        private readonly MulticastService _mDNSService;
        private readonly ServiceDiscovery _serviceDiscovery;
        private readonly ISessionManager _sessionManager;
        private readonly INodeRegister _nodeRegister;

        private Fabric? _fabric;
        private Dictionary<int, ICommissioner> _commissioners;

        public event IMatterController.ReconnectedToNode ReconnectedToNodeEvent;
        public event IMatterController.CommissionableNodeDiscovered CommissionableNodeDiscoveredEvent;
        public event IMatterController.MatterNodeAddedToFabric MatterNodeAddedToFabricEvent;

        public MatterController(IFabricStorageProvider fabricStorageProvider)
        {
            _fabricManager = new FabricManager(fabricStorageProvider);
            _commissioners = new Dictionary<int, ICommissioner>();
            _nodeRegister = new NodeRegister();
            _nodeRegister.CommissionableNodeDiscoveredEvent += (object sender, CommissionableNodeDiscoveredEventArgs args) =>
            {
                CommissionableNodeDiscoveredEvent?.Invoke(this);
            };
            _sessionManager = new SessionManager(_nodeRegister);
            //_mDNSService = new mDNSService(new NullLogger<mDNSService>());
            _mDNSService = new MulticastService();
            _serviceDiscovery = new ServiceDiscovery(_mDNSService);
        }

        public Task<ICommissioner> CreateCommissionerAsync()
        {
            if (_fabric == null)
            {
                throw new InvalidOperationException($"Fabric not initialized. Call {nameof(InitAsync)}() first.");
            }

            ICommissioner commissioner = new NetworkCommissioner(_fabric, _nodeRegister);

            _commissioners.Add(commissioner.Id, commissioner);

            return Task.FromResult(commissioner);
        }

        public async Task InitAsync()
        {
            // Start the mDNS service to discover nodes.
            //
            //_mDNSService.ServiceDiscovered += (sender, args) =>
            _mDNSService.AnswerReceived += _mDNSService_AnswerReceived;
            //_serviceDiscovery.ServiceDiscovered += _serviceDiscovery_ServiceDiscovered;
            //_serviceDiscovery.ServiceInstanceDiscovered += _serviceDiscovery_ServiceInstanceDiscovered;

            _fabric = await _fabricManager.GetAsync("Test");
            _fabric.NodeAdded += OnNodeAddedToFabric;
        }

        private void _mDNSService_AnswerReceived(object? sender, MessageEventArgs e)
        {
            var servers = e.Message.Answers.OfType<SRVRecord>();

            foreach (var server in servers)
            {
                //Console.WriteLine($"host '{server.Target}' for '{server.Name}'");

                if (server.Name.ToString().Contains("_matter._tcp.local"))
                {
                    var addresses = e.Message.Answers.OfType<AddressRecord>();
                    _nodeRegister.AddCommissionedNode(server.Name.ToString().Replace("_matter._tcp.local", ""), server.Port, addresses.Select(a => a.Address.ToString()).ToArray());
                }
                else if (server.Name.ToString().Contains("_matterc._udp.local"))
                {
                    var txtRecords = e.Message.Answers.OfType<TXTRecord>();

                    var recordWithDiscriminator = txtRecords.FirstOrDefault(x => x.Strings.Any(y => y.StartsWith("D=")));

                    ushort discriminator = 0;

                    if (recordWithDiscriminator is not null)
                    {
                        var discriminatorString = recordWithDiscriminator.Strings.Single(x => x.StartsWith("D="));
                        discriminator = ushort.Parse(discriminatorString.Substring(2)); // Remove "d=" prefix
                    }

                    var addresses = e.Message.Answers.OfType<AddressRecord>();

                    if (discriminator == 0 || !addresses.Any())
                    {
                        continue;
                    }

                    _nodeRegister.AddCommissionableNode(server.Name.ToString().Replace("_matterc._tcp.local", ""), discriminator, server.Port, addresses.Select(a => a.Address.ToString()).ToArray());
                }

                // Ask for the host IP addresses.
                //_mDNSService.SendQuery(server.Target, type: DnsType.A);
                //_mDNSService.SendQuery(server.Target, type: DnsType.AAAA);
            }

            // Is this an answer to host addresses?
            //var addresses = e.Message.Answers.OfType<AddressRecord>();
            //foreach (var address in addresses)
            //{
            //    Console.WriteLine($"host '{address.Name}' at {address.Address}");
            //}
        }

        //private void _serviceDiscovery_ServiceInstanceDiscovered(object? sender, ServiceInstanceDiscoveryEventArgs e)
        //{
        //    var instanceName = e.ServiceInstanceName.ToString();

        //    if (instanceName.Contains("_matter._tcp.local") || instanceName.Contains("_matterc._udp.local"))
        //    {
        //        _mDNSService.SendQuery(e.ServiceInstanceName, type: DnsType.SRV);

        //        //args.TxtValues.TryGetValue("D", out string? discriminator);
        //        //_nodeRegister.AddCommissionableNode(args.Name.Replace("_matterc._tcp.local", ""), discriminator, args.Addresses);
        //    }
        //}

        //private void _serviceDiscovery_ServiceDiscovered(object? sender, DomainName args)
        //{
        //if (args.Contains("_matter._tcp.local"))
        //{
        //    _nodeRegister.AddCommissionedNode(args.Name.Replace("_matter._tcp.local", ""), args.Addresses);
        //}
        //else if (args.Name.Contains("_matterc._udp.local"))
        //{
        //    args.TxtValues.TryGetValue("D", out string? discriminator);
        //    _nodeRegister.AddCommissionableNode(args.Name.Replace("_matterc._tcp.local", ""), discriminator, args.Addresses);
        //}
        //}

        public async Task RunAsync()
        {
            if (_fabric == null)
            {
                throw new InvalidOperationException($"Fabric not initialized. Call {nameof(InitAsync)}() first.");
            }

            // Start the mDNS service to discover commissionable and commissioned nodes.
            //
            //_mDNSService.Perform(new ServiceDiscovery("_matter._tcp.local.", "_matterc._udp.local."));
            _mDNSService.Start();
            _mDNSService.SendQuery("_matterc._tcp.local");
            _mDNSService.SendQuery("_matter._tcp.local");

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
