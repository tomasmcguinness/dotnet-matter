using Matter.Core.TLV;

namespace Matter.Core.InteractionModel
{
    internal class InvokeResponse
    {
        public InvokeResponse(MatterTLV payload)
        {
            // NO OP
        }

        public bool SuppressResponse { get; }

        public List<InvokeresponseIB> InvokeResponses { get; } = [];
    }
}
