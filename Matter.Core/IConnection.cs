
namespace Matter.Core
{
    public interface IConnection
    {
        event EventHandler ConnectionClosed;

        void Close();

        IConnection OpenConnection();

        Task<byte[]> ReadAsync(CancellationToken token);

        Task SendAsync(byte[] message);
    }
}
