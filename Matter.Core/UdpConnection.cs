using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Matter.Core
{
    internal class UdpConnection : IConnection
    {
        private UdpClient _udpClient;
        private Channel<MessageFrame> MessageFrameChannel = Channel.CreateBounded<MessageFrame>(5);

        public UdpConnection()
        {
            _udpClient = new UdpClient(11000);
            IPAddress address = IPAddress.Parse("172.16.47.60");
            _udpClient.Connect(address, 5540);
        }

        public async Task<MessageFrame> ReadAsync()
        {
            var receiveResult = await _udpClient.ReceiveAsync();
            MessageFrame messageFrame = new MessageFrame(receiveResult.Buffer);
            return messageFrame;
        }

        public async Task SendAsync(MessageFrame message)
        {
            var writer = new MatterMessageWriter();

            message.Serialize(writer);

            var bytes = writer.GetBytes();

            await _udpClient.SendAsync(bytes);
        }
    }
}
