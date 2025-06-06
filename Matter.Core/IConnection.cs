
namespace Matter.Core
{
    public interface IConnection
    {
        event EventHandler ConnectionClosed;

        void Close();

        IConnection OpenConnection();

        Task<byte[]> ReadAsync();

        Task SendAsync(byte[] message);
    }
}
