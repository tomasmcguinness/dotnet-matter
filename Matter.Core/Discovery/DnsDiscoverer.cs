using System.Threading.Channels;
using Zeroconf;

namespace Matter.Core.Discovery
{
    public class DnsDiscoverer
    {
        public Channel<string> ReceivedDataChannel { get; } = Channel.CreateBounded<string>(5);

        public void DiscoverCommissionableNodes()
        {
            var observable = ZeroconfResolver.BrowseDomainsContinuous(scanTime: TimeSpan.FromSeconds(30), 2, 2000);

            observable.Subscribe(
                domain =>
                {
                    Console.WriteLine($"Domain found: {domain}");
                    ReceivedDataChannel.Writer.TryWrite(domain.ToString());
                },
                error =>
                {
                    Console.WriteLine($"Error: {error}");
                }
                );

            //var responses = await ZeroconfResolver.ResolveAsync(domains.Select(g => g.Key));

            //foreach (var resp in responses)
            //{
            //    Console.WriteLine(resp);
            //}

            //IReadOnlyList<IZeroconfHost> results = await ZeroconfResolver.ResolveAsync("_matterc._udp.local.", TimeSpan.FromSeconds(30), 5, 2000);

            //foreach (var result in results)
            //{
            //    Console.WriteLine(result.DisplayName);
            //}

            //Console.WriteLine("Finished ZeroConf discovery!");
        }
    }
}
