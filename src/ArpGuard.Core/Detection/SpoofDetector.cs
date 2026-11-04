namespace ArpGuard;

public enum Severity { Info, Warning, Danger }

public sealed record Finding(Severity Severity, string Message);

public sealed record DuplicateGroup(int InterfaceIndex, string Mac, IReadOnlyList<ArpEntry> Entries)
{
    /// <summary>Stable identity so 'watch' reports each group only once.</summary>
    public string Key => $"{InterfaceIndex}|{Mac}|{string.Join(",", Entries.Select(e => e.Ip))}";
}

public static class SpoofDetector
{
    public static List<Finding> Analyze(Snapshot s, PinStore pins)
    {
        var findings = new List<Finding>();

        foreach (var iface in s.Interfaces)
        {
            foreach (var gwIp in iface.Gateways)
            {
                var entry = s.Find(iface.Index, gwIp);
                if (entry is null || !entry.HasMac)
                {
                    findings.Add(new(Severity.Warning,
                        $"Couldn't resolve the MAC of gateway {gwIp} on {iface.Name}. Is the router reachable?"));
                    continue;
                }

                findings.Add(entry.IsStatic
                    ? new(Severity.Info, $"Gateway {gwIp} -> {entry.Mac} on {iface.Name} (pinned)")
                    : new(Severity.Info, $"Gateway {gwIp} -> {entry.Mac} on {iface.Name} (dynamic, not pinned)"));

                if (MacUtil.IsLocallyAdministered(entry.Mac))
                    findings.Add(new(Severity.Warning,
                        $"Gateway {gwIp} has a locally administered MAC ({entry.Mac}). Routers normally use a " +
                        "manufacturer-assigned MAC, while laptops and phones often randomize theirs. " +
                        "Double-check this is really your router."));

                var pin = pins.Find(gwIp);
                if (pin is not null && pin.Mac != entry.Mac)
                    findings.Add(new(Severity.Danger,
                        $"Gateway {gwIp} is {entry.Mac}, but you pinned {pin.Mac}. Either the pin was removed " +
                        "and something else answered, or you replaced your router."));
            }
        }

        findings.AddRange(FindDuplicates(s).Select(g => Describe(g, s)));
        return findings;
    }

    /// <summary>Several IPs on one interface answering with the same MAC.</summary>
    public static List<DuplicateGroup> FindDuplicates(Snapshot s) =>
        s.ActiveHosts()
            .GroupBy(e => (e.InterfaceIndex, e.Mac))
            .Where(g => g.Count() > 1)
            .Select(g => new DuplicateGroup(
                g.Key.InterfaceIndex, g.Key.Mac, g.OrderBy(e => IpUtil.ToUInt32(e.Ip)).ToList()))
            .ToList();

    public static Finding Describe(DuplicateGroup group, Snapshot s)
    {
        string name = s.InterfaceName(group.InterfaceIndex);
        var gateway = group.Entries.FirstOrDefault(s.IsGateway);
        if (gateway is not null)
        {
            var others = string.Join(", ", group.Entries.Where(e => e != gateway).Select(e => e.Ip));
            return new(Severity.Danger,
                $"Gateway {gateway.Ip} shares MAC {group.Mac} with {others} on {name}. This is the classic " +
                "sign of ARP spoofing: another device on your network is claiming to be your router.");
        }

        var ips = string.Join(", ", group.Entries.Select(e => e.Ip));
        return new(Severity.Warning,
            $"These IPs share MAC {group.Mac} on {name}: {ips}. This can mean spoofing, but Wi-Fi " +
            "extenders, mesh nodes and devices with several IPs cause it too.");
    }
}
