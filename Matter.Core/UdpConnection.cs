﻿using System.Net;
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
        private IPEndPoint _Endpoint = new IPEndPoint(IPAddress.IPv6Any, 0);

        private readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();

        public event EventHandler ConnectionClosed;

        public SemaphoreSlim AcknowledgementReceived { get; init; } = new SemaphoreSlim(0);

        public UdpConnection(IPAddress address, ushort port)
        {
            _ipAddress = address;
            _port = port;

            _cancellationTokenSource = new CancellationTokenSource();

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                _udpClient = new UdpClient(AddressFamily.InterNetwork);
            }
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                _udpClient = new UdpClient(AddressFamily.InterNetworkV6);
            }

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

        public async Task<byte[]> ReadAsync(CancellationToken token)
        {
            return await _receivedDataChannel.Reader.ReadAsync(token);
        }

        public async Task SendAsync(byte[] bytes)
        {
            await _udpClient!.SendAsync(bytes, _cancellationTokenSource.Token);

            // TODO Ensure we get an acknowledgement of the frame we just sent!
            //
            //await AcknowledgementReceived.WaitAsync();
        }
    }
}
