using System.Net;

namespace ArpGuard;

/// <summary>
/// Remembers each IP's MAC and reports changes. Call <see cref="Start"/> once, then
/// <see cref="Tick"/> on a timer. Not thread-safe: don't overlap calls.
/// </summary>
/// <param name="capturePackets">
/// Also inspect packets with Npcap (if installed). The ARP table alone can't show spoofing aimed at
/// the router, or any spoofing once the gateway is pinned.
/// </param>
public sealed class ArpWatcher(PinStore pins, bool capturePackets = true) : IDisposable
{
    // Pinging the gateway now and then keeps its entry fresh, so a forged reply shows up quickly.
    private static readonly TimeSpan GatewayProbeInterval = TimeSpan.FromSeconds(10);

    private readonly Dictionary<(int Interface, IPAddress Ip), string> _lastKnownMac = new();
    private readonly HashSet<string> _reportedDuplicates = new();
    private DateTime _lastProbe;
    private WireMonitor? _monitor;

    public int DeviceCount => _lastKnownMac.Count;

    /// <summary>The snapshot taken by the most recent Start/Tick.</summary>
    public Snapshot? Latest { get; private set; }

    /// <summary>Records the baseline and returns what's already wrong (or notable) with it.</summary>
    public List<Finding> Start()
    {
        var s = Snapshot.Take(probeGateways: true);
        _lastProbe = DateTime.UtcNow;
        Latest = s;

        foreach (var e in s.ActiveHosts())
            _lastKnownMac[(e.InterfaceIndex, e.Ip)] = e.Mac;
        foreach (var g in SpoofDetector.FindDuplicates(s))
            _reportedDuplicates.Add(g.Key);

        var findings = SpoofDetector.Analyze(s, pins);
        if (capturePackets)
            _monitor = WireMonitor.Start(s, pins, findings);
        return findings;
    }

    /// <summary>True if packets are being inspected as well as the ARP table.</summary>
    public bool CapturingPackets => _monitor is not null;

    public void Dispose()
    {
        _monitor?.Dispose();
        _monitor = null;
    }

    /// <summary>Takes a new snapshot and returns only what changed since the last one.</summary>
    public List<Finding> Tick()
    {
        bool probe = DateTime.UtcNow - _lastProbe >= GatewayProbeInterval;
        if (probe)
            _lastProbe = DateTime.UtcNow;
        var s = Snapshot.Take(probe);
        Latest = s;

        var findings = new List<Finding>();
        foreach (var e in s.ActiveHosts())
        {
            var key = (e.InterfaceIndex, e.Ip);
            if (!_lastKnownMac.TryGetValue(key, out string? oldMac))
            {
                _lastKnownMac[key] = e.Mac;
                findings.Add(new(Severity.Info, $"New device {e.Ip} -> {e.Mac} on {s.InterfaceName(e.InterfaceIndex)}"));
                continue;
            }
            if (oldMac == e.Mac)
                continue;

            _lastKnownMac[key] = e.Mac;
            bool isGateway = s.IsGateway(e);
            findings.Add(isGateway || pins.Find(e.Ip) is not null
                ? new(Severity.Danger,
                    $"{(isGateway ? "Gateway" : "Pinned device")} {e.Ip} changed MAC {oldMac} -> {e.Mac}! " +
                    "Something may be impersonating it.")
                : new(Severity.Warning,
                    $"{e.Ip} changed MAC {oldMac} -> {e.Mac}. Could be spoofing, or a device that reconnected " +
                    "with a new random MAC."));
        }

        foreach (var g in SpoofDetector.FindDuplicates(s))
        {
            if (_reportedDuplicates.Add(g.Key))
                findings.Add(SpoofDetector.Describe(g, s));
        }

        if (_monitor is not null)
            findings.AddRange(_monitor.Drain());
        return findings;
    }
}
