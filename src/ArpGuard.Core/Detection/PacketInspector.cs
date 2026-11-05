using System.Net;

namespace ArpGuard;

/// <summary>The MAC a gateway is supposed to have, and how ArpGuard knows it.</summary>
public sealed record ExpectedMac(string Mac, MacSource Source);

public enum MacSource
{
    /// <summary>Pinned (by ArpGuard or a static entry): the user vouched for it.</summary>
    Pinned,
    /// <summary>Whatever the ARP table said when capture started. Could already be spoofed.</summary>
    ArpTable,
    /// <summary>The first MAC seen claiming the gateway's IP on the wire.</summary>
    FirstSeen,
}

/// <summary>
/// Checks raw Ethernet frames for spoofing the ARP table can't show:
/// <list type="bullet">
/// <item>ARP packets from a second MAC claiming the gateway's IP. Windows silently ignores these
/// when the gateway is pinned, so they never reach the ARP table.</item>
/// <item>ARP packets from another MAC claiming <em>this computer's</em> IP: that's the half of the
/// attack aimed at the router, which pinning can't stop.</item>
/// <item>Internet traffic addressed to this computer that arrives from a MAC other than the
/// router's: proof that something is relaying the traffic sent back to you.</item>
/// </list>
/// Each problem is reported once. Not thread-safe: use one inspector per capture thread.
/// </summary>
public sealed class PacketInspector
{
    private readonly NetInterface _iface;
    private readonly Dictionary<IPAddress, ExpectedMac?> _gateways;
    private readonly HashSet<string> _reported = new();

    public PacketInspector(NetInterface iface, IReadOnlyDictionary<IPAddress, ExpectedMac?> gateways)
    {
        _iface = iface;
        _gateways = new(gateways);
    }

    /// <summary>The BPF filter that lets through just the packets <see cref="Inspect"/> looks at.</summary>
    public static string CaptureFilter(NetInterface iface)
    {
        if (iface.Address is null || iface.Mask is null || iface.Mac.Length == 0)
            return "arp";
        var network = new IPAddress(BitConverter.GetBytes(
            BitConverter.ToUInt32(iface.Address.GetAddressBytes()) & BitConverter.ToUInt32(iface.Mask.GetAddressBytes())));
        return $"arp or (ip and ether dst {iface.Mac.Replace('-', ':')} and not src net {network}/{IpUtil.PrefixLength(iface.Mask)})";
    }

    /// <returns>A new problem this frame reveals, or null.</returns>
    public Finding? Inspect(ReadOnlySpan<byte> frame) => FrameParser.Parse(frame) is { } f ? Inspect(f) : null;

    public Finding? Inspect(ParsedFrame frame) => frame.Kind switch
    {
        FrameKind.Arp => InspectArp(frame),
        FrameKind.IPv4 => InspectIPv4(frame),
        _ => null,
    };

    private Finding? InspectArp(ParsedFrame frame)
    {
        string kind = frame.ArpKind;
        string senderMac = frame.ArpSenderMac!;
        var senderIp = frame.ArpSenderIp!;
        if (senderIp.Equals(IPAddress.Any) || !IsHostMac(senderMac))
            return null; // ARP probes (RFC 5227) carry no claim

        if (_gateways.TryGetValue(senderIp, out var expected))
        {
            if (expected is null)
            {
                _gateways[senderIp] = new ExpectedMac(senderMac, MacSource.FirstSeen);
                return null;
            }
            if (expected.Mac == senderMac || !_reported.Add($"gw|{senderIp}|{senderMac}"))
                return null;
            if (MacUtil.IsSibling(expected.Mac, senderMac))
                return new(Severity.Info,
                    $"Gateway {senderIp} also answers ARP as {senderMac} on {_iface.Name}. That's next to its MAC " +
                    $"{expected.Mac}, so it's most likely another interface of the same router.");

            return expected.Source == MacSource.Pinned
                ? new(Severity.Danger,
                    $"{senderMac} sent {kind} claiming to be your gateway {senderIp} on {_iface.Name}, which " +
                    $"you pinned to {expected.Mac}. Your pin stops this computer from believing it, but a device " +
                    "doing this is usually also telling your router that it is this computer, so traffic coming " +
                    "back to you can still go through it, or be blocked by it.")
                : new(Severity.Danger,
                    $"Two MACs claim to be gateway {senderIp} on {_iface.Name}: {expected.Mac} " +
                    $"({(expected.Source == MacSource.ArpTable ? "in your ARP table when capture started" : "seen first")}) " +
                    $"and {senderMac}. One of them is impersonating your router. Compare them with the MAC on " +
                    "your router's label or admin page.");
        }

        if (senderIp.Equals(_iface.Address) && _iface.Mac.Length > 0 && senderMac != _iface.Mac &&
            _reported.Add($"self|{senderMac}"))
        {
            return new(Severity.Danger,
                $"{senderMac} sent {kind} claiming to be this computer ({senderIp}) on {_iface.Name}. Devices " +
                "that believe it, usually your router, send your incoming traffic to it instead of to you, so it " +
                "can watch or block your connection. Pinning on this computer can't prevent that; it has to be " +
                "fixed on the router.");
        }
        return null;
    }

    private Finding? InspectIPv4(ParsedFrame frame)
    {
        if (!IsInternetTrafficToMe(_iface, frame))
            return null;
        string srcMac = frame.SrcMac;
        var srcIp = frame.IpSource!;

        var known = _gateways.Values.OfType<ExpectedMac>().ToList();
        if (known.Count == 0 || known.Any(g => g.Mac == srcMac) || !_reported.Add($"relay|{srcMac}"))
            return null;
        if (known.FirstOrDefault(g => MacUtil.IsSibling(g.Mac, srcMac)) is { } sibling)
            return new(Severity.Info,
                $"Some internet traffic reaches you from {srcMac} on {_iface.Name}. That's next to your router's " +
                $"MAC {sibling.Mac}, so it's most likely the same router sending from another interface " +
                "(often its Wi-Fi radio).");

        string routers = string.Join(" or ", known.Select(g => g.Mac).Distinct());
        return new(Severity.Danger,
            $"Traffic from {srcIp} (outside your network) reached this computer from {srcMac} on {_iface.Name}, " +
            $"not from your router ({routers}). Another device is relaying the traffic sent back to you, which " +
            "is how ARP spoofing intercepts or blocks a connection. (A second router on your network with its " +
            "own route can also cause this.)");
    }

    /// <summary>An ARP sender that's a real host (not a probe, broadcast or empty address).</summary>
    internal static bool IsHostMac(string mac) => !MacUtil.IsZero(mac) && !MacUtil.IsMulticastOrBroadcast(mac);

    /// <summary>An IPv4 packet sent to this computer's MAC from outside its subnet, i.e. via a router.</summary>
    internal static bool IsInternetTrafficToMe(NetInterface iface, ParsedFrame frame)
    {
        if (frame.Kind != FrameKind.IPv4 || frame.DstMac != iface.Mac)
            return false;
        var src = frame.IpSource!;
        var b = src.GetAddressBytes();
        bool linkLocal = b[0] == 169 && b[1] == 254;
        return !iface.Contains(src) && IpUtil.IsUnicast(src) && !linkLocal;
    }
}
