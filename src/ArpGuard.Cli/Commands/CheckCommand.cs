namespace ArpGuard;

internal static class CheckCommand
{
    public static async Task<int> RunAsync(CliArgs cli)
    {
        cli.Allow("online", "listen");
        bool online = cli.Flag("online");
        int listen = cli.GetInt("listen", 0, 1, 3600);

        var s = Snapshot.Take(probeGateways: true);
        if (!s.Interfaces.Any(i => i.Gateways.Count > 0))
            Ui.Warn("No active interface has a default gateway. Are you connected to a network?");

        var pins = PinStore.Load(Ui.Warn);
        var findings = SpoofDetector.Analyze(s, pins);
        if (listen > 0)
            findings.AddRange(Listen(s, pins, listen));
        findings = findings.OrderBy(f => f.Severity).ToList();
        foreach (var finding in findings)
            Ui.Show(finding);

        if (online)
            await ShowGatewayVendorsAsync(s);

        Console.WriteLine();
        if (findings.Any(f => f.Severity == Severity.Danger))
        {
            Ui.Danger("Possible ARP spoofing detected. Don't pin anything until you've investigated.");
            return 2;
        }
        if (findings.Any(f => f.Severity == Severity.Warning))
            Ui.Warn("Nothing conclusive, but review the warnings above.");
        else
            Ui.Ok("No signs of ARP spoofing.");
        return 0;
    }

    /// <summary>Inspects packets for a while, catching spoofing the ARP table can't show.</summary>
    private static List<Finding> Listen(Snapshot s, PinStore pins, int seconds)
    {
        var findings = new List<Finding>();
        using var monitor = WireMonitor.Start(s, pins, findings);
        if (monitor is null)
            return findings;

        Console.WriteLine($"Listening to network traffic for {seconds}s...");
        Thread.Sleep(TimeSpan.FromSeconds(seconds));
        findings.AddRange(monitor.Drain());
        return findings;
    }

    private static async Task ShowGatewayVendorsAsync(Snapshot s)
    {
        bool first = true;
        foreach (var iface in s.Interfaces)
        {
            foreach (var gwIp in iface.Gateways)
            {
                var entry = s.Find(iface.Index, gwIp);
                if (entry is null || !entry.HasMac || MacUtil.IsLocallyAdministered(entry.Mac))
                    continue; // randomized MACs have no vendor

                if (!first)
                    await Task.Delay(1100); // the free API allows about 1 request per second
                first = false;

                string? vendor = await VendorLookup.LookupAsync(entry.Mac);
                if (vendor is null)
                    Ui.Warn($"Vendor lookup for gateway {gwIp} failed (offline or rate-limited).");
                else
                    Ui.Info($"Gateway {gwIp} vendor: {vendor}. Does that match your router's brand?");
            }
        }
    }
}
