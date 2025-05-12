namespace Matter.Core
{
    public interface IMatterController
    {
        void Init();

        Task<ICommissioner> CreateCommissionerAsync();
    }
}