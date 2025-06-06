namespace Matter.Core
{
    public interface INodeRegister
    {
        void AddCommissionedNode(string nodeIdAndCompressedFabricIdentifier, string[] addresses);

        string[] GetCommissionedNodeAddresses(string nodeIdAndCompressedFabricIdentifier);
    }
}