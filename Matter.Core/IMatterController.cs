namespace Matter.Core
{
    public interface IMatterController
    {
        void Start();

        Task<ICommissioner> CreateCommissionerAsync();
    }
}