namespace Matter.Core
{
    public interface ICommissioner
    {
        int Id { get; }

        Task CommissionNodeAsync(int discriminator);
    }
}