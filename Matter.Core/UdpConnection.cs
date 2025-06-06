using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Matter.Core
{
    internal class UdpConnection : IConnection
    {
        private UdpClient? _udpClient;
        private Channel<byte[]> _receivedDataChannel = Channel.CreateBounded<byte[]>(5);
        private IPAddress _ipAddress;
        private ushort _port;
        private IPEndPoint _Endpoint = new IPEndPoint(IPAddress.Any, 0);

        private AsyncCallback _ReceiveCallback = null;

        private readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();

        public event EventHandler ConnectionClosed;

        public UdpConnection(IPAddress address, ushort port)
        {
            _ipAddress = address;
            _port = port;

            _cancellationTokenSource = new CancellationTokenSource();

            _udpClient = new UdpClient(0);
            _udpClient.Connect(address, port);

            Task.Factory.StartNew(ProcessIncomingData);
        }

        public IConnection OpenConnection()
        {
            return new UdpConnection(_ipAddress, _port);
        }

        public void Close()
        {
            _cancellationTokenSource.Cancel();

            _udpClient!.Close();
            _udpClient = null;
        }

        public bool IsConnectionEstablished => _udpClient != null && _udpClient.Client.Connected;

        public async Task ProcessIncomingData()
        {
            try
            {
                while (!_cancellationTokenSource.IsCancellationRequested)
                {
                    UdpReceiveResult result = await _udpClient!.ReceiveAsync();

                    var bytes = result.Buffer;

                    Console.WriteLine("UdpConnection: Received {0} bytes from {1}:{2}", bytes.Length, _Endpoint!.Address, _Endpoint!.Port);

                    await _receivedDataChannel.Writer.WriteAsync(bytes);
                }
            }
            catch
            {
                Console.WriteLine("UdpConnection: Error receiving data, closing connection.");
                ConnectionClosed?.Invoke(this, EventArgs.Empty);
            }
        }

        //private async void DataReceived(IAsyncResult ar)
        //{
        //    try
        //    {
        //        var bytes = _udpClient!.EndReceive(ar, ref _Endpoint);

        //        Console.WriteLine("UdpConnection: Received {0} bytes from {1}:{2}", bytes.Length, _Endpoint!.Address, _Endpoint!.Port);

        //        await _receivedDataChannel.Writer.WriteAsync(bytes);

        //        _udpClient.BeginReceive(_ReceiveCallback = (ar) => DataReceived(ar), null);
        //    }
        //    catch
        //    {
        //        _cancellationTokenSource.Cancel();

        //        _udpClient?.Close();
        //        _udpClient = null;

        //        ConnectionClosed?.Invoke(this, EventArgs.Empty);
        //    }
        //}

        public async Task<byte[]> ReadAsync()
        {
            return await _receivedDataChannel.Reader.ReadAsync(_cancellationTokenSource.Token);
        }

        public async Task SendAsync(byte[] bytes)
        {
            await _udpClient!.SendAsync(bytes, _cancellationTokenSource.Token);
        }
    }
}
