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

        var store = PinStore.Load(Ui.Warn);
        var s = Snapshot.Take(probeGateways: true);
        var (iface, ip) = Target.Resolve(s, cli);
        var plan = PinService.Plan(s, iface, ip, macArg, store);

        if (plan.AlreadyPinned)
        {
            PinService.Apply(plan, store); // just records it if it was pinned outside ArpGuard
            Ui.Ok($"{ip} is already pinned to {plan.Mac} on {iface.Name}.");
            return 0;
        }

        // Pinning while being spoofed would lock in the attacker's MAC, so check first.
        foreach (var problem in plan.Problems)
            Ui.Show(problem);
        if (plan.HasDanger && !force)
            throw new ArpGuardException(
                "Refusing to pin while there are signs of spoofing - you could end up pinning the attacker's MAC. " +
                "Investigate first, or use --force if you're sure the MAC is right.");
        if (plan.MacDiffersFromTable)
            Ui.Warn($"The ARP table currently says {ip} is {plan.Current!.Mac}, but you asked for {plan.Mac}.");

        Console.WriteLine();
        Console.WriteLine($"  Interface: {iface.Name} (interface {iface.Index})");
        Console.WriteLine($"  IP:        {ip}");
        Console.WriteLine($"  MAC:       {plan.Mac}");
        Console.WriteLine();
        Console.WriteLine("This entry survives reboots. If you replace your router (or your ISP swaps it),");
        Console.WriteLine($"run 'arpguard unpin --ip {ip}' or you'll lose your connection.");
        if (!yes && !Ui.Confirm("Pin this entry?"))
        {
            Console.WriteLine("Cancelled.");
            return 1;
        }

        PinService.Apply(plan, store);
        Ui.Ok($"Pinned {ip} -> {plan.Mac} on {iface.Name}. Undo with: arpguard unpin --ip {ip}");
        return 0;
    }
}
