using System.Collections.Concurrent;

namespace Matter.Core
{
    internal class NodeRegister : INodeRegister
    {
        private readonly ConcurrentDictionary<string, string[]> _commissionedNodes = new ConcurrentDictionary<string, string[]>();

        public void AddCommissionedNode(string nodeIdAndCompressedFabricIdentifier, string[] addresses)
        {
            _commissionedNodes.AddOrUpdate(nodeIdAndCompressedFabricIdentifier, addresses, (key, oldValue) => addresses);
        }

        public string[] GetCommissionedNodeAddresses(string nodeIdAndCompressedFabricIdentifier)
        {
            if (_commissionedNodes.TryGetValue(nodeIdAndCompressedFabricIdentifier, out var addresses))
            {
                return addresses;
            }

            return Array.Empty<string>();
        }
    }
}
