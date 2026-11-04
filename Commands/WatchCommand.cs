using System.Net;

namespace ArpGuard;

internal static class WatchCommand
{
    private const int GatewayProbeSeconds = 10;

    public static int Run(CliArgs cli)
    {
        cli.Allow("interval", "log", "no-beep");
        int interval = cli.GetInt("interval", 2, 1, 3600);
        string? logPath = cli.Get("log");
        bool beep = !cli.Flag("no-beep");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        var pins = PinStore.Load();
        var lastKnownMac = new Dictionary<(int Interface, IPAddress Ip), string>();
        var reportedDuplicates = new HashSet<string>();

        void Report(Finding f)
        {
            string stamp = DateTime.Now.ToString("HH:mm:ss");
            Console.Write(stamp + " ");
            Ui.Show(f);
            if (f.Severity == Severity.Danger && beep)
                Console.Beep();
            if (logPath is not null)
            {
                try { File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {f.Severity.ToString().ToUpperInvariant()} {f.Message}{Environment.NewLine}"); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    Ui.Warn($"Couldn't write to {logPath}: {ex.Message}");
                }
            }
        }

        // Baseline: report what's already wrong, then only report changes.
        var s = Snapshot.Take(probeGateways: true);
        foreach (var e in s.ActiveHosts())
            lastKnownMac[(e.InterfaceIndex, e.Ip)] = e.Mac;
        foreach (var f in SpoofDetector.Analyze(s, pins))
            Report(f);
        foreach (var g in SpoofDetector.FindDuplicates(s))
            reportedDuplicates.Add(g.Key);

        Console.WriteLine($"Watching {lastKnownMac.Count} devices, checking every {interval}s. Press Ctrl+C to stop.");

        var lastProbe = DateTime.UtcNow;
        while (!cts.Token.WaitHandle.WaitOne(TimeSpan.FromSeconds(interval)))
        {
            // Pinging the gateway now and then keeps its entry fresh, so a forged reply shows up quickly.
            bool probe = (DateTime.UtcNow - lastProbe).TotalSeconds >= GatewayProbeSeconds;
            if (probe)
                lastProbe = DateTime.UtcNow;
            s = Snapshot.Take(probe);

            foreach (var e in s.ActiveHosts())
            {
                var key = (e.InterfaceIndex, e.Ip);
                if (!lastKnownMac.TryGetValue(key, out string? oldMac))
                {
                    lastKnownMac[key] = e.Mac;
                    Report(new(Severity.Info, $"New device {e.Ip} -> {e.Mac} on {s.InterfaceName(e.InterfaceIndex)}"));
                    continue;
                }
                if (oldMac == e.Mac)
                    continue;

                lastKnownMac[key] = e.Mac;
                bool critical = s.IsGateway(e) || pins.Find(e.Ip) is not null;
                Report(critical
                    ? new(Severity.Danger,
                        $"{(s.IsGateway(e) ? "Gateway" : "Pinned device")} {e.Ip} changed MAC {oldMac} -> {e.Mac}! " +
                        "Something may be impersonating it.")
                    : new(Severity.Warning,
                        $"{e.Ip} changed MAC {oldMac} -> {e.Mac}. Could be spoofing, or a device that reconnected " +
                        "with a new random MAC."));
            }

            foreach (var g in SpoofDetector.FindDuplicates(s))
            {
                if (reportedDuplicates.Add(g.Key))
                    Report(SpoofDetector.Describe(g, s));
            }
        }

        Console.WriteLine("Stopped.");
        return 0;
    }
}
