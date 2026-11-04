namespace ArpGuard;

internal static class ListCommand
{
    public static int Run(CliArgs cli)
    {
        cli.Allow("all");
        bool all = cli.Flag("all");

        var s = Snapshot.Take(probeGateways: true);
        var duplicateMacs = EntryText.DuplicateMacs(s);

        var groups = s.Entries
            .Where(e => all || (e.IsUsable && s.InterfaceFor(e.InterfaceIndex) is not null))
            .GroupBy(e => e.InterfaceIndex)
            .OrderBy(g => g.Key)
            .ToList();

        if (groups.Count == 0)
        {
            Console.WriteLine("The ARP table has no entries on active interfaces.");
            return 0;
        }

        foreach (var group in groups)
        {
            var iface = s.InterfaceFor(group.Key);
            Ui.Line(ConsoleColor.White, iface?.Describe() ?? $"Interface {group.Key} (not active)");

            var rows = group
                .OrderBy(e => IpUtil.ToUInt32(e.Ip))
                .Select(e => new[] { e.Ip.ToString(), e.HasMac ? e.Mac : "-", EntryText.State(e), EntryText.Notes(e, s, duplicateMacs) })
                .ToList();
            Ui.Table(["IP", "MAC", "TYPE", "NOTES"], rows);
            Console.WriteLine();
        }

        if (!all)
            Ui.Line(ConsoleColor.DarkGray, "Hiding multicast, broadcast, unresolved and inactive-interface entries. Use --all to show them.");
        return 0;
    }
}
