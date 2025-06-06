using Matter.Core.Fabrics;

namespace Matter.Core.Sessions
{
    public interface ISessionManager
    {
        Task Start(Fabric fabric);
    }
}