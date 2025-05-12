namespace Matter.Core
{
    public interface ICommissioner
    {
        int Id { get; }

        void CommissionDevice(int discriminator);
    }
}