using Matter.Core;

namespace Matter.Tests
{
    internal class FakeConnection : IConnection
    {
        public event EventHandler ConnectionClosed;

        public Task<byte[]> ReadAsync()
        {
            return Task.FromResult(new byte[0]);
        }

        public Task SendAsync(byte[] message)
        {
            return Task.CompletedTask;
        }

        public void Close()
        {
            // Do nothing
        }

        public IConnection OpenConnection()
        {
            return new FakeConnection();
        }
    }
}