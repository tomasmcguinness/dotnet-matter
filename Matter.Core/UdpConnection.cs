using System.Net;
using System.Net.Sockets;

namespace Matter.Core
{
    internal class UdpConnection : IConnection
    {
        private UdpClient _udpClient;

        public UdpConnection()
        {
            _udpClient = new UdpClient(11000);
            IPAddress address = IPAddress.Parse("172.16.47.60");
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
