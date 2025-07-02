using Matter.Core.Commissioning;

namespace Matter.Core
{
    public interface ICommissioner
    {
        int Id { get; }

        Task CommissionNodeAsync(CommissioningPayload payload);
    }
}