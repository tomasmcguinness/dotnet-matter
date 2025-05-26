
namespace Matter.Core
{
    public interface IConnection
    {
        void Close();

        IConnection CreateNewConnection();

        Task<byte[]> ReadAsync();

        Task SendAsync(byte[] message);
    }
}
