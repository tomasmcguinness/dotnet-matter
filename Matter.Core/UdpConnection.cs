using System.Net;
using System.Net.Sockets;

namespace Matter.Core
{
    internal class UdpConnection : IConnection
    {
        private UdpClient _udpClient;

        public UdpConnection()
        {
            _udpClient = new UdpClient(0);
            IPAddress address = IPAddress.Parse("127.0.0.1");
            _udpClient.Connect(address, 5540);
        }

        public async Task<byte[]> ReadAsync()
        {
            var receiveResult = await _udpClient.ReceiveAsync();

            return receiveResult.Buffer;
        }

        public async Task SendAsync(byte[] bytes)
        {
            await _udpClient.SendAsync(bytes);
        }
    }
}
