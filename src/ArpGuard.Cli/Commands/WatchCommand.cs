namespace ArpGuard;

internal static class WatchCommand
{
    public static int Run(CliArgs cli)
    {
        cli.Allow("interval", "log", "no-beep", "no-capture");
        int interval = cli.GetInt("interval", 2, 1, 3600);
        string? logPath = cli.Get("log");
        bool beep = !cli.Flag("no-beep");
        bool capture = !cli.Flag("no-capture");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        void Report(Finding f)
        {
            Console.Write(DateTime.Now.ToString("HH:mm:ss") + " ");
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

        using var watcher = new ArpWatcher(PinStore.Load(Ui.Warn), capture);
        watcher.Start().ForEach(Report);
        Console.WriteLine($"Watching {watcher.DeviceCount} devices, checking every {interval}s" +
                          $"{(watcher.CapturingPackets ? " and inspecting packets as they arrive" : "")}. Press Ctrl+C to stop.");

        while (!cts.Token.WaitHandle.WaitOne(TimeSpan.FromSeconds(interval)))
            watcher.Tick().ForEach(Report);

        Console.WriteLine("Stopped.");
        return 0;
    }
}
