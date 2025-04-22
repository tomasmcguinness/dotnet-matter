using Zeroconf;

namespace Matter.Core.Discovery
{
    internal class DnsDiscoverer
    {
        public async Task DiscoverCommissionableNodes()
        {
            ILookup<string, string> domains = await ZeroconfResolver.BrowseDomainsAsync(scanTime: TimeSpan.FromSeconds(30), 2, 2000, (s1, s2) =>
            {
                Console.WriteLine($"Found device {s1},{s2}");
            });

            var responses = await ZeroconfResolver.ResolveAsync(domains.Select(g => g.Key));

            foreach (var resp in responses)
            {
                Console.WriteLine(resp);
            }

            IReadOnlyList<IZeroconfHost> results = await ZeroconfResolver.ResolveAsync("_matterc._udp.local.", TimeSpan.FromSeconds(30), 5, 2000);

            foreach (var result in results)
            {
                Console.WriteLine(result.DisplayName);
            }
            ;

            Console.WriteLine("Finished ZeroConf discovery!");
        }
    }
}
