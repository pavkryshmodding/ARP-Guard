using System.Net;

namespace ArpGuard;

/// <summary>
/// Tallies who claims which address on one network during a capture, so a test can show the
/// evidence (not just the verdict). Not thread-safe.
/// </summary>
public sealed class TrafficSummary(NetInterface iface, IReadOnlyDictionary<IPAddress, ExpectedMac?> gateways)
{
    private readonly Dictionary<IPAddress, Dictionary<string, int>> _gatewayClaims = new();
    private readonly Dictionary<string, int> _selfClaims = new();
    private readonly Dictionary<string, int> _internetSenders = new();

    public int Frames { get; private set; }
    public int ArpFrames { get; private set; }
    public int InternetFrames { get; private set; }

    public void Add(ParsedFrame frame)
    {
        Frames++;
        if (frame.Kind == FrameKind.Arp)
        {
            var ip = frame.ArpSenderIp!;
            string mac = frame.ArpSenderMac!;
            if (!iface.Contains(ip) || !PacketInspector.IsHostMac(mac))
                return; // another network's ARP, or a probe
            ArpFrames++;
            if (gateways.ContainsKey(ip))
                Bump(_gatewayClaims.TryGetValue(ip, out var d) ? d : _gatewayClaims[ip] = new(), mac);
            else if (ip.Equals(iface.Address))
                Bump(_selfClaims, mac);
        }
        else if (PacketInspector.IsInternetTrafficToMe(iface, frame))
        {
            InternetFrames++;
            Bump(_internetSenders, frame.SrcMac);
        }
    }

    public List<string> Describe()
    {
        var lines = new List<string>
        {
            $"{Frames} packets inspected: {ArpFrames} ARP on this network, {InternetFrames} from the internet addressed to you.",
        };

        foreach (var (gw, expected) in gateways)
        {
            string label = expected is null ? "unknown" : expected.Source switch
            {
                MacSource.Pinned => $"pinned to {expected.Mac}",
                _ => $"ARP table says {expected.Mac}",
            };
            lines.Add($"Claiming to be gateway {gw} ({label}):");
            if (!_gatewayClaims.TryGetValue(gw, out var claims))
                lines.Add("  nobody. Routers can stay quiet for minutes; try a longer test.");
            else
                lines.AddRange(Rows(claims, mac => expected is null ? "" : RouterNote(mac, [expected.Mac], "NOT your router")));
        }

        if (_selfClaims.Count > 0)
        {
            lines.Add($"Claiming to be this computer ({iface.Address}, really {iface.Mac}):");
            lines.AddRange(Rows(_selfClaims, mac => mac == iface.Mac ? "  this computer" : "  IMPERSONATING YOU"));
        }

        var routerMacs = gateways.Values.OfType<ExpectedMac>().Select(g => g.Mac).ToHashSet();
        lines.Add("Internet traffic to you arrived from:");
        if (_internetSenders.Count == 0)
            lines.Add("  nothing captured.");
        else
            lines.AddRange(Rows(_internetSenders, mac => RouterNote(mac, routerMacs, "NOT your router: something is relaying")));
        return lines;
    }

    private static string RouterNote(string mac, IEnumerable<string> routerMacs, string otherwise) =>
        routerMacs.Contains(mac) ? "  your router" :
        routerMacs.Any(r => MacUtil.IsSibling(r, mac)) ? "  your router (another of its interfaces)" :
        "  " + otherwise;

    private static IEnumerable<string> Rows(Dictionary<string, int> counts, Func<string, string> note) =>
        counts.OrderByDescending(kv => kv.Value).Select(kv => $"  {kv.Key}  {kv.Value,6} packets{note(kv.Key)}");

    private static void Bump(Dictionary<string, int> counts, string key) =>
        counts[key] = counts.GetValueOrDefault(key) + 1;
}
