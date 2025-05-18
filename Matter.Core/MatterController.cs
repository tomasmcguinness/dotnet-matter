using Matter.Core.Commissioning;
using Matter.Core.Fabrics;

namespace Matter.Core
{
    public class MatterController : IMatterController
    {
        private readonly FabricManager _fabricManager;
        private Fabric _fabric;
        private Dictionary<int, ICommissioner> _commissioners;
        private readonly IFabricStorageProvider _fabricStorageProvider;

        public event IMatterController.MatterNodeAddedToFabric MatterNodeAddedToFabricEvent;

        public MatterController(IFabricStorageProvider fabricStorageProvider)
        {
            _fabricManager = new FabricManager(fabricStorageProvider);
            _commissioners = new Dictionary<int, ICommissioner>();
            _fabricStorageProvider = fabricStorageProvider;
        }

        public Task<ICommissioner> CreateCommissionerAsync()
        {
            if (_fabric == null)
            {
                throw new InvalidOperationException("Fabric not initialized. Call Init() first.");
            }

            ICommissioner commissioner = new NetworkCommissioner(_fabric);

            _commissioners.Add(commissioner.Id, commissioner);

            return Task.FromResult(commissioner);
        }

        public async Task InitAsync()
        {
            _fabric = await _fabricManager.GetAsync("Test");
            _fabric.NodeAdded += OnNodeAddedToFabric;
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
    }
}
