
namespace Matter.Core
{
    internal interface IConnection
    {
        Task<byte[]> ReadAsync();

        Task SendAsync(byte[] message);
    }
}
