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
    private readonly Dictionary<ushort, int> _etherTypes = new();
    private readonly Dictionary<(string Mac, IPAddress Ip), (int Requests, int Replies)> _arpSenders = new();

    public int Frames { get; private set; }
    public int ArpFrames { get; private set; }
    public int InternetFrames { get; private set; }

    public void Add(ParsedFrame frame)
    {
        Frames++;
        _etherTypes[frame.EtherType] = _etherTypes.GetValueOrDefault(frame.EtherType) + 1;
        if (frame.Kind == FrameKind.Arp)
        {
            var ip = frame.ArpSenderIp!;
            string mac = frame.ArpSenderMac!;
            if (!iface.Contains(ip) || !PacketInspector.IsHostMac(mac))
                return; // another network's ARP, or a probe
            ArpFrames++;
            var (req, rep) = _arpSenders.GetValueOrDefault((mac, ip));
            _arpSenders[(mac, ip)] = frame.ArpOp == 2 ? (req, rep + 1) : (req + 1, rep);
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
            "Frame types: " + string.Join(", ", _etherTypes.OrderByDescending(kv => kv.Value)
                .Select(kv => $"{EtherTypeName(kv.Key)} {kv.Value}")),
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
        if (_arpSenders.Count > 0)
        {
            lines.Add($"Busiest ARP senders on this network ({_arpSenders.Count} in total):");
            foreach (var ((mac, ip), (req, rep)) in _arpSenders.OrderByDescending(kv => kv.Value.Requests + kv.Value.Replies).Take(8))
            {
                string who = mac == iface.Mac ? "  this computer" :
                    routerMacs.Any(r => MacUtil.IsSibling(r, mac)) ? "  your router" : "";
                lines.Add($"  {mac}  {ip,-15} {req,6} requests {rep,6} replies{who}");
            }
        }

        lines.Add("Internet traffic to you arrived from:");
        if (_internetSenders.Count == 0)
            lines.Add("  nothing captured.");
        else
            lines.AddRange(Rows(_internetSenders, mac => RouterNote(mac, routerMacs, "NOT your router: something is relaying")));
        return lines;
    }

    private static string EtherTypeName(ushort type) => type switch
    {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        0x888E => "EAPOL",
        0x88CC => "LLDP",
        _ => $"0x{type:x4}",
    };

    private static string RouterNote(string mac, IEnumerable<string> routerMacs, string otherwise) =>
        routerMacs.Contains(mac) ? "  your router" :
        routerMacs.Any(r => MacUtil.IsSibling(r, mac)) ? "  your router (another of its interfaces)" :
        "  " + otherwise;

    private static IEnumerable<string> Rows(Dictionary<string, int> counts, Func<string, string> note) =>
        counts.OrderByDescending(kv => kv.Value).Select(kv => $"  {kv.Key}  {kv.Value,6} packets{note(kv.Key)}");

    private static void Bump(Dictionary<string, int> counts, string key) =>
        counts[key] = counts.GetValueOrDefault(key) + 1;
}
