namespace Matter.Core
{
    public interface IMatterController
    {
        Task InitAsync();

        Task<ICommissioner> CreateCommissionerAsync();
    }
}