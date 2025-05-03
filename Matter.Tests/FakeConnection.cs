using Matter.Core;

namespace Matter.Tests
{
    internal class FakeConnection : IConnection
    {
        public Task<byte[]> ReadAsync()
        {
            return Task.FromResult(new byte[0]);
        }

        public Task SendAsync(byte[] message)
        {
            return Task.CompletedTask;
        }
    }
}