using Matter.Core.Events;

namespace Matter.Core
{
    public interface IMatterController
    {
        delegate void MatterNodeAddedToFabric(object sender, MatterNodeAddedToFabricEventArgs e);
        event MatterNodeAddedToFabric MatterNodeAddedToFabricEvent;

        Task InitAsync();

        Task<ICommissioner> CreateCommissionerAsync();
    }
}