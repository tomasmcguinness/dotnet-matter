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
            if (_fabric == null)
            {
                throw new InvalidOperationException("Fabric not initialized. Call Init() first.");
            }

            ICommissioner commissioner = new NetworkCommissioner(_fabric);

            _commissioners.Add(commissioner.Id, commissioner);

            return Task.FromResult(commissioner);
        }

        public void Init()
        {
            _fabric = Fabric.CreateNew("Test");
        }
    }
}
