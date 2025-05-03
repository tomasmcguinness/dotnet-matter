
namespace Matter.Core
{
    public interface IConnection
    {
        Task<byte[]> ReadAsync();

        Task SendAsync(byte[] message);
    }
}
