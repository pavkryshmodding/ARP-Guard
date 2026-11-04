using System.Net;

namespace ArpGuard;

internal static class UnpinCommand
{
    public static int Run(CliArgs cli)
    {
        cli.Allow("ip", "interface", "all", "yes");
        bool all = cli.Flag("all");
        bool yes = cli.Flag("yes");
        if (all && (cli.Get("ip") is not null || cli.GetInterfaceIndex() is not null))
            throw new ArpGuardException("--all can't be combined with --ip or --interface.");
        Admin.Require("unpin");

        var store = PinStore.Load(Ui.Warn);

        List<IPAddress> ips;
        int? onlyInterface = null;
        if (all)
        {
            ips = store.Pins.Select(p => IPAddress.Parse(p.Ip)).ToList();
            if (ips.Count == 0)
            {
                Console.WriteLine("ArpGuard hasn't pinned anything.");
                return 0;
            }
        }
        else
        {
            onlyInterface = cli.GetInterfaceIndex();
            // Don't probe here: if a stale pin broke the connection, pinging would just hang.
            ips = [cli.GetIp("ip") ?? Target.Resolve(Snapshot.Take(probeGateways: false), cli).Ip];
        }

        var targets = PinService.FindStatic(ips, onlyInterface);
        if (targets.Count == 0)
        {
            int forgotten = ips.Count(ip => store.Find(ip) is not null);
            if (forgotten > 0)
            {
                ips.ForEach(store.Remove);
                store.Save();
            }
            Console.WriteLine($"No static ARP entry found for {string.Join(", ", ips)}." +
                (forgotten > 0 ? " Removed it from ArpGuard's saved pins." : ""));
            return 0;
        }

        Console.WriteLine("Will remove:");
        foreach (var t in targets)
            Console.WriteLine($"  {t.Ip} -> {t.Mac} (interface {t.InterfaceIndex})");
        if (!yes && !Ui.Confirm("Continue?"))
        {
            Console.WriteLine("Cancelled.");
            return 1;
        }

        var stillStatic = PinService.Unpin(targets, store, ips);
        foreach (var e in stillStatic)
            Ui.Warn($"{e.Ip} still shows as static on interface {e.InterfaceIndex}. Try: netsh interface ipv4 delete neighbors interface={e.InterfaceIndex} address={e.Ip}");
        if (stillStatic.Count > 0)
            return 1;

        Ui.Ok($"Removed {targets.Count} static entr{(targets.Count == 1 ? "y" : "ies")}. Windows will learn the MAC dynamically again.");
        return 0;
    }
}
