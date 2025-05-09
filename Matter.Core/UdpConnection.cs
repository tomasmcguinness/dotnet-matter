using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Matter.Core
{
    internal class UdpConnection : IConnection
    {
        private UdpClient _udpClient;
        private Thread _readingThread;
        private Channel<byte[]> _receivedDataChannel = Channel.CreateBounded<byte[]>(5);

        public UdpConnection()
        {
            _udpClient = new UdpClient(0);
            IPAddress address = IPAddress.Parse("127.0.0.1");
            _udpClient.Connect(address, 5540);

            _readingThread = new Thread(new ThreadStart(ReadAvailableData));
            _readingThread.Start();
        }

        private async void ReadAvailableData()
        {
            do
            {
                var receiveResult = await _udpClient.ReceiveAsync();

                //Console.WriteLine("UDP: Received {0} bytes from {1}:{2}", receiveResult.Buffer.Length, receiveResult.RemoteEndPoint.Address, receiveResult.RemoteEndPoint.Port);

                await _receivedDataChannel.Writer.WriteAsync(receiveResult.Buffer.ToArray());

            } while (true);
        }

        public async Task<byte[]> ReadAsync()
        {
            return await _receivedDataChannel.Reader.ReadAsync();
        }

        public async Task SendAsync(byte[] bytes)
        {
            await _udpClient.SendAsync(bytes);
        }
    }
}
