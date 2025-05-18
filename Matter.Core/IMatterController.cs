using Matter.Core.Events;
using Matter.Core.Fabrics;

namespace Matter.Core
{
    public interface IMatterController
    {
        delegate void MatterNodeAddedToFabric(object sender, MatterNodeAddedToFabricEventArgs e);
        event MatterNodeAddedToFabric MatterNodeAddedToFabricEvent;

        Task InitAsync();

        Task<ICommissioner> CreateCommissionerAsync();

        Task<IEnumerable<Node>> GetNodesAsync();
    }
}