
namespace Matter.Core
{
    public interface IConnection
    {
        void Close();

        Task<byte[]> ReadAsync();

        Task SendAsync(byte[] message);
    }
}
