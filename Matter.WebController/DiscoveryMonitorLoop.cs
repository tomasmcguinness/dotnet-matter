using Matter.Core.Discovery;

namespace Matter.WebController
{
    public class DiscoveryMonitorLoop
    {
        private readonly CancellationToken _cancellationToken;

        public DiscoveryMonitorLoop(IHostApplicationLifetime applicationLifetime)
        {
            _cancellationToken = applicationLifetime.ApplicationStopping;
        }

        public void StartMonitorLoop()
        {
            Task.Run(async () => await MonitorAsync());
        }

        private async ValueTask MonitorAsync()
        {
            var dnsDiscoverer = new DnsDiscoverer();

            dnsDiscoverer.DiscoverCommissionableNodes();

            while (!_cancellationToken.IsCancellationRequested)
            {
                var newDevice = await dnsDiscoverer.ReceivedDataChannel.Reader.ReadAsync();
            }
        }
    }
}
