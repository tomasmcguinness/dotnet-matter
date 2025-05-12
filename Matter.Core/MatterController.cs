using Matter.Core.Commissioning;
using Matter.Core.Fabrics;

namespace Matter.Core
{
    public class MatterController : IMatterController
    {
        private Fabric _fabric;
        private Dictionary<int, ICommissioner> _commissioners;

        public MatterController()
        {
            _commissioners = new Dictionary<int, ICommissioner>();
        }

        public Task<ICommissioner> CreateCommissionerAsync()
        {
            ICommissioner commissioner = new NetworkCommissioner(_fabric);

            // Hook into some events here, so we know the score!

            _commissioners.Add(commissioner.Id, commissioner);

            return Task.FromResult(commissioner);
        }

        public void Start()
        {
            LoadFabric();
        }

        private void LoadFabric()
        {
            _fabric = Fabric.CreateNew("Test");
        }
    }
}
