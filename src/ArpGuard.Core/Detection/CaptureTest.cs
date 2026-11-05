using System.Net;
using System.Net.NetworkInformation;

namespace ArpGuard;

/// <param name="CaptureFiles">Raw captures that were kept (see the saveAs parameter).</param>
public sealed record CaptureTestResult(
    IReadOnlyList<Finding> Findings, IReadOnlyList<string> Report, IReadOnlyList<string> CaptureFiles)
{
    public bool Danger => Findings.Any(f => f.Severity == Severity.Danger);
}

/// <summary>
/// Captures traffic for a fixed time and reports who claims which address, using either Npcap
/// (what 'watch' uses) or Windows' built-in pktmon (no install needed, but admin only).
/// Both ping 1.1.1.1 once a second meanwhile, so there's internet traffic coming back to inspect.
/// </summary>
public static class CaptureTest
{
    private static readonly IPAddress PingTarget = IPAddress.Parse("1.1.1.1");

    /// <param name="saveAs">If set, keep the raw capture as "{saveAs}_if{interface}.pcap".</param>
    public static CaptureTestResult RunNpcap(
        Snapshot s, PinStore pins, TimeSpan duration, CancellationToken ct, string? saveAs = null)
    {
        string version = PcapCapture.Version() ?? throw new ArpGuardException(
            $"Npcap isn't installed. Get it from {WireMonitor.NpcapUrl}, or use the pktmon test instead.");

        var report = new List<string> { $"Using {version}." };
        var findings = new List<Finding>();
        var files = new List<string>();
        var sessions = new List<(NetInterface Iface, PcapCapture Capture, Session Session)>();
        try
        {
            foreach (var iface in GatewayInterfaces(s))
            {
                PcapCapture capture;
                try
                {
                    capture = PcapCapture.Open(iface.Id, PacketInspector.CaptureFilter(iface));
                }
                catch (ArpGuardException ex)
                {
                    findings.Add(new(Severity.Warning, $"Can't capture on {iface.Name}: {ex.Message}"));
                    continue;
                }
                sessions.Add((iface, capture, new Session(s, iface, pins)));

                if (saveAs is null)
                    continue;
                string file = $"{saveAs}_if{iface.Index}.pcap";
                try
                {
                    capture.SaveTo(file);
                    files.Add(file);
                }
                catch (ArpGuardException ex)
                {
                    findings.Add(new(Severity.Warning, $"Testing anyway, but couldn't save the capture: {ex.Message}"));
                }
            }
            if (sessions.Count == 0)
                return new(findings, report, files);

            var deadline = DateTime.UtcNow + duration;
            string? error = null;
            using (StartPinging())
            {
                var threads = sessions.Select(x => new Thread(() =>
                {
                    var buffer = new byte[PcapCapture.SnapLength];
                    while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
                    {
                        var r = x.Capture.Next(buffer, out int length, out string? e);
                        if (r == CaptureResult.Packet && FrameParser.Parse(buffer.AsSpan(0, length)) is { } frame)
                            x.Session.Add(frame);
                        else if (r == CaptureResult.Error)
                        {
                            error = $"Capture on {x.Iface.Name} stopped early: {e}";
                            return;
                        }
                    }
                }) { IsBackground = true }).ToList();
                threads.ForEach(t => t.Start());
                threads.ForEach(t => t.Join());
            }
            ct.ThrowIfCancellationRequested();
            if (error is not null)
                findings.Add(new(Severity.Warning, error));

            foreach (var x in sessions)
                x.Session.AppendTo(report, findings);
            return new(findings, report, files);
        }
        finally
        {
            sessions.ForEach(x => x.Capture.Dispose());
        }
    }

    /// <summary>Needs administrator rights. Refuses to run if pktmon is already capturing for someone else.</summary>
    /// <param name="saveAs">If set, keep the raw capture as "{saveAs}.pcapng".</param>
    public static CaptureTestResult RunPktmon(
        Snapshot s, PinStore pins, TimeSpan duration, CancellationToken ct, string? saveAs = null)
    {
        var interfaces = GatewayInterfaces(s).ToList();
        string baseName = Path.Combine(Path.GetTempPath(), $"arpguard-pktmon-{Guid.NewGuid():N}");
        string etl = baseName + ".etl", pcap = baseName + ".pcapng";
        try
        {
            var (code, output) = ProcessRunner.Run("pktmon",
                $"start --capture --comp nics --pkt-size {PcapCapture.SnapLength} --file-name \"{etl}\"");
            if (code != 0)
                throw new ArpGuardException(
                    $"pktmon couldn't start (exit code {code}): {output.Trim()} " +
                    "It needs administrator rights, and fails if another pktmon capture is already running " +
                    "(stop that one with 'pktmon stop').");

            try
            {
                using (StartPinging())
                    ct.WaitHandle.WaitOne(duration);
            }
            finally
            {
                ProcessRunner.Run("pktmon", "stop");
            }
            ct.ThrowIfCancellationRequested();

            (code, output) = ProcessRunner.Run("pktmon", $"etl2pcap \"{etl}\" --out \"{pcap}\"");
            if (code != 0 || !File.Exists(pcap))
                throw new ArpGuardException($"pktmon couldn't convert its capture (exit code {code}): {output.Trim()}");

            var (frames, skipped) = PcapNg.ReadEthernetFrames(pcap);
            var report = new List<string>
            {
                $"pktmon recorded {frames.Count + skipped} packets on all network adapters" +
                (skipped > 0 ? $" ({skipped} weren't Ethernet and were skipped)." : ".") +
                " It can log a packet more than once, so counts may be inflated.",
            };
            var findings = new List<Finding>();
            foreach (var iface in interfaces)
            {
                var session = new Session(s, iface, pins);
                foreach (var bytes in frames)
                    if (FrameParser.Parse(bytes) is { } frame)
                        session.Add(frame);
                session.AppendTo(report, findings);
            }

            var files = new List<string>();
            if (saveAs is not null)
            {
                try
                {
                    File.Move(pcap, saveAs + ".pcapng");
                    files.Add(saveAs + ".pcapng");
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    findings.Add(new(Severity.Warning, $"Couldn't save the capture: {ex.Message}"));
                }
            }
            return new(findings, report, files);
        }
        finally
        {
            TryDelete(etl);
            TryDelete(pcap); // no-op once moved
        }
    }

    private static IEnumerable<NetInterface> GatewayInterfaces(Snapshot s)
    {
        var list = s.Interfaces.Where(i => i.Gateways.Count > 0).ToList();
        if (list.Count == 0)
            throw new ArpGuardException("No active network has a gateway. Are you connected?");
        return list;
    }

    private static Timer StartPinging() => new(_ =>
    {
        try
        {
            using var ping = new Ping();
            ping.Send(PingTarget, 800);
        }
        catch (PingException) { }
    }, null, TimeSpan.Zero, TimeSpan.FromSeconds(1));

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>One network's inspector and tally during a test.</summary>
    private sealed class Session
    {
        private readonly NetInterface _iface;
        private readonly PacketInspector _inspector;
        private readonly TrafficSummary _summary;
        private readonly List<Finding> _findings = new();

        public Session(Snapshot s, NetInterface iface, PinStore pins)
        {
            _iface = iface;
            var expected = WireMonitor.ExpectedGatewayMacs(s, iface, pins);
            _inspector = new PacketInspector(iface, expected);
            _summary = new TrafficSummary(iface, expected);
        }

        public void Add(ParsedFrame frame)
        {
            _summary.Add(frame);
            if (_inspector.Inspect(frame) is { } f)
                _findings.Add(f);
        }

        public void AppendTo(List<string> report, List<Finding> findings)
        {
            report.Add("");
            report.Add($"-- {_iface.Describe()} --");
            report.AddRange(_summary.Describe());
            findings.AddRange(_findings);
        }
    }
}
