using Matter.Core.Events;
using Matter.Core.Fabrics;
using Org.BouncyCastle.Math;

namespace Matter.Core
{
    public interface IMatterController
    {
        delegate void MatterNodeAddedToFabric(object sender, MatterNodeAddedToFabricEventArgs e);
        event MatterNodeAddedToFabric MatterNodeAddedToFabricEvent;

        delegate void ReconnectedToNode(object sender, Node node);
        event ReconnectedToNode ReconnectedToNodeEvent;

        Task InitAsync();

        Task<ICommissioner> CreateCommissionerAsync();

        Task<IEnumerable<Node>> GetNodesAsync();

        Task<Node> GetNodeAsync(BigInteger nodeId);

        Task RunAsync();
    }
}