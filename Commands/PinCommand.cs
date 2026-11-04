namespace ArpGuard;

internal static class PinCommand
{
    public static int Run(CliArgs cli)
    {
        cli.Allow("ip", "mac", "interface", "yes", "force");
        bool yes = cli.Flag("yes");
        bool force = cli.Flag("force");
        string? macArg = cli.Get("mac");
        Admin.Require("pin");

        var store = PinStore.Load();
        var s = Snapshot.Take(probeGateways: true);
        var (iface, ip) = Target.Resolve(s, cli);
        var current = s.Find(iface.Index, ip);

        string mac;
        if (macArg is not null)
        {
            if (!MacUtil.TryNormalize(macArg, out mac))
                throw new CliException($"'{macArg}' isn't a valid MAC address (expected e.g. aa-bb-cc-dd-ee-ff).");
            if (MacUtil.IsMulticastOrBroadcast(mac) || MacUtil.IsZero(mac))
                throw new CliException($"{mac} is a multicast/broadcast/empty address, not a device.");
        }
        else if (current is { HasMac: true })
        {
            mac = current.Mac;
        }
        else
        {
            throw new CliException($"Couldn't find a MAC for {ip} in the ARP table. Make sure it's online, or pass --mac.");
        }

        if (current is { IsStatic: true } && current.Mac == mac)
        {
            Ui.Ok($"{ip} is already pinned to {mac} on {iface.Name}.");
            if (store.Find(ip) is null)
            {
                store.Upsert(new PinRecord(ip.ToString(), mac, iface.Index, iface.Name, DateTimeOffset.Now));
                store.Save();
            }
            return 0;
        }

        // Pinning while being spoofed would lock in the attacker's MAC, so check first.
        var problems = SpoofDetector.Analyze(s, store).Where(f => f.Severity >= Severity.Warning).ToList();
        foreach (var problem in problems)
            Ui.Show(problem);
        if (problems.Any(p => p.Severity == Severity.Danger) && !force)
            throw new CliException(
                "Refusing to pin while there are signs of spoofing - you could end up pinning the attacker's MAC. " +
                "Investigate first, or use --force if you're sure the MAC is right.");

        if (current is { HasMac: true } && current.Mac != mac)
            Ui.Warn($"The ARP table currently says {ip} is {current.Mac}, but you asked for {mac}.");

        Console.WriteLine();
        Console.WriteLine($"  Interface: {iface.Name} (interface {iface.Index})");
        Console.WriteLine($"  IP:        {ip}");
        Console.WriteLine($"  MAC:       {mac}");
        Console.WriteLine();
        Console.WriteLine("This entry survives reboots. If you replace your router (or your ISP swaps it),");
        Console.WriteLine($"run 'arpguard unpin --ip {ip}' or you'll lose your connection.");
        if (!yes && !Ui.Confirm("Pin this entry?"))
        {
            Console.WriteLine("Cancelled.");
            return 1;
        }

        Netsh.AddStaticNeighbor(iface.Index, ip, mac);

        var after = IpHelper.GetIPv4Neighbors().FirstOrDefault(e => e.InterfaceIndex == iface.Index && e.Ip.Equals(ip));
        if (after is not { IsStatic: true } || after.Mac != mac)
            throw new CliException("netsh reported success, but the entry isn't showing as static. Check with 'arpguard list'.");

        store.Upsert(new PinRecord(ip.ToString(), mac, iface.Index, iface.Name, DateTimeOffset.Now));
        store.Save();
        Ui.Ok($"Pinned {ip} -> {mac} on {iface.Name}. Undo with: arpguard unpin --ip {ip}");
        return 0;
    }
}
