namespace Matter.Core
{
    public interface ICommissioner
    {
        int Id { get; }

        Task CommissionDeviceAsync(int discriminator);
    }
}