using System.Net;

namespace ArpGuard;

/// <summary>What pinning would do, worked out before anything is changed.</summary>
public sealed record PinPlan(
    NetInterface Interface, IPAddress Ip, string Mac, ArpEntry? Current, IReadOnlyList<Finding> Problems)
{
    public bool AlreadyPinned => Current is { IsStatic: true } && Current.Mac == Mac;

    /// <summary>Pinning now could lock in an attacker's MAC.</summary>
    public bool HasDanger => Problems.Any(p => p.Severity == Severity.Danger);

    public bool MacDiffersFromTable => Current is { HasMac: true } && Current.Mac != Mac;
}

/// <summary>Pin/unpin logic shared by the CLI and the GUI. Changing entries needs admin rights.</summary>
public static class PinService
{
    public static PinPlan Plan(Snapshot s, NetInterface iface, IPAddress ip, string? macOverride, PinStore store)
    {
        var current = s.Find(iface.Index, ip);

        string mac;
        if (macOverride is not null)
        {
            if (!MacUtil.TryNormalize(macOverride, out mac))
                throw new ArpGuardException($"'{macOverride}' isn't a valid MAC address (expected e.g. aa-bb-cc-dd-ee-ff).");
            if (MacUtil.IsMulticastOrBroadcast(mac) || MacUtil.IsZero(mac))
                throw new ArpGuardException($"{mac} is a multicast/broadcast/empty address, not a device.");
        }
        else if (current is { HasMac: true })
        {
            mac = current.Mac;
        }
        else
        {
            throw new ArpGuardException($"Couldn't find a MAC for {ip} in the ARP table. Make sure it's online.");
        }

        var problems = SpoofDetector.Analyze(s, store).Where(f => f.Severity >= Severity.Warning).ToList();
        return new PinPlan(iface, ip, mac, current, problems);
    }

    /// <summary>Adds the persistent static entry, checks it took effect, and records it.</summary>
    public static void Apply(PinPlan plan, PinStore store)
    {
        if (!plan.AlreadyPinned)
        {
            Netsh.AddStaticNeighbor(plan.Interface.Index, plan.Ip, plan.Mac);

            var after = IpHelper.GetIPv4Neighbors()
                .FirstOrDefault(e => e.InterfaceIndex == plan.Interface.Index && e.Ip.Equals(plan.Ip));
            if (after is not { IsStatic: true } || after.Mac != plan.Mac)
                throw new ArpGuardException("netsh reported success, but the entry isn't showing as static.");
        }

        store.Upsert(new PinRecord(plan.Ip.ToString(), plan.Mac, plan.Interface.Index, plan.Interface.Name, DateTimeOffset.Now));
        store.Save();
    }

    /// <summary>Static ARP entries for these IPs, optionally limited to one interface.</summary>
    public static List<ArpEntry> FindStatic(IEnumerable<IPAddress> ips, int? onlyInterface = null)
    {
        var wanted = ips.ToList();
        return IpHelper.GetIPv4Neighbors()
            .Where(e => e.IsStatic && wanted.Contains(e.Ip) && (onlyInterface is null || e.InterfaceIndex == onlyInterface))
            .ToList();
    }

    /// <summary>
    /// Removes the entries and forgets them (plus any extra IPs in <paramref name="alsoForget"/>).
    /// Returns the entries that are somehow still static afterwards (empty means success).
    /// </summary>
    public static List<ArpEntry> Unpin(IReadOnlyList<ArpEntry> targets, PinStore store, IEnumerable<IPAddress>? alsoForget = null)
    {
        foreach (var t in targets)
        {
            Netsh.DeleteNeighbor(t.InterfaceIndex, t.Ip);
            store.Remove(t.Ip);
        }
        foreach (var ip in alsoForget ?? [])
            store.Remove(ip);
        store.Save();

        return IpHelper.GetIPv4Neighbors()
            .Where(e => e.IsStatic && targets.Any(t => t.InterfaceIndex == e.InterfaceIndex && t.Ip.Equals(e.Ip)))
            .ToList();
    }
}
