using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Matter.Core
{
    internal class UdpConnection : IConnection
    {
        private UdpClient? _udpClient;
        private Thread _readingThread;
        private Channel<byte[]> _receivedDataChannel = Channel.CreateBounded<byte[]>(5);
        private CancellationTokenSource _cancellationTokenSource;
        private IPAddress _ipAddress;
        private ushort _port;

        public UdpConnection(IPAddress address, ushort port)
        {
            _ipAddress = address;
            _port = port;

            _cancellationTokenSource = new CancellationTokenSource();

            _udpClient = new UdpClient(0);
            _udpClient.Connect(address, port);

            _readingThread = new Thread(new ThreadStart(ReadAvailableData));
            _readingThread.Start();
        }

        public IConnection CreateNewConnection()
        {
            return new UdpConnection(_ipAddress, _port);
        }

        public void Close()
        {
            _cancellationTokenSource.Cancel();

            _readingThread.Join();
            _udpClient!.Close();
            _udpClient = null;
        }

        private async void ReadAvailableData()
        {
            do
            {
                try
                {
                    var receiveResult = await _udpClient!.ReceiveAsync(_cancellationTokenSource.Token);

                    //Console.WriteLine("UDP: Received {0} bytes from {1}:{2}", receiveResult.Buffer.Length, receiveResult.RemoteEndPoint.Address, receiveResult.RemoteEndPoint.Port);

                    await _receivedDataChannel.Writer.WriteAsync(receiveResult.Buffer.ToArray());
                }
                catch
                {
                    // NOOP
                }


            } while (!_cancellationTokenSource.Token.IsCancellationRequested);
        }

        public async Task<byte[]> ReadAsync()
        {
            try
            {
                return await _receivedDataChannel.Reader.ReadAsync();
            }
            catch
            {
                return new byte[0];
            }
        }

        public async Task SendAsync(byte[] bytes)
        {
            await _udpClient!.SendAsync(bytes, _cancellationTokenSource.Token);
        }
    }
}
