namespace Matter.Core
{
    public class ServerNode
    {
        private UdpServer _listener;

        public ServerNode()
        {

        }

        public async Task StartAsync()
        {

            _listener = new UdpServer();

            while (true) // Use a cancellation token?
            {
                var receivedData = await _listener.ReadAsync();
            }
        }
    }
}
