using System.Collections.Concurrent;
using System.Net;

namespace ArpGuard;

/// <summary>
/// Captures packets with Npcap on every network that has a gateway and runs them through a
/// <see cref="PacketInspector"/> on a background thread. Collect what it found with <see cref="Drain"/>.
/// </summary>
public sealed class WireMonitor : IDisposable
{
    public const string NpcapUrl = "https://npcap.com/#download";

    private readonly ConcurrentQueue<Finding> _findings = new();
    private readonly List<Thread> _threads = new();
    private volatile bool _stopping;

    private WireMonitor() { }

    /// <summary>Starts capturing. Returns null if nothing could be captured.</summary>
    /// <param name="notes">Gets told what's being captured, or why it isn't.</param>
    public static WireMonitor? Start(Snapshot s, PinStore pins, List<Finding> notes)
    {
        string? version = PcapCapture.Version();
        if (version is null)
        {
            notes.Add(new(Severity.Warning,
                "Npcap isn't installed, so ArpGuard can only read the ARP table. That misses spoofing aimed at " +
                $"your router, and any spoofing at all once the gateway is pinned. Install Npcap from {NpcapUrl} " +
                "to also check the packets themselves."));
            return null;
        }

        var monitor = new WireMonitor();
        foreach (var iface in s.Interfaces.Where(i => i.Gateways.Count > 0))
        {
            PcapCapture capture;
            try
            {
                capture = PcapCapture.Open(iface.Id, PacketInspector.CaptureFilter(iface));
            }
            catch (ArpGuardException ex)
            {
                notes.Add(new(Severity.Warning, $"Can't capture packets on {iface.Name}: {ex.Message}"));
                continue;
            }

            var inspector = new PacketInspector(iface, ExpectedGatewayMacs(s, iface, pins));
            var thread = new Thread(() => monitor.Run(iface, capture, inspector))
            {
                IsBackground = true,
                Name = $"ArpGuard capture ({iface.Name})",
            };
            monitor._threads.Add(thread);
            thread.Start();
            notes.Add(new(Severity.Info, $"Checking packets on {iface.Name} ({version})."));
        }

        return monitor._threads.Count > 0 ? monitor : null;
    }

    /// <summary>Everything found since the last call. Safe to call from any thread.</summary>
    public List<Finding> Drain()
    {
        var result = new List<Finding>();
        while (_findings.TryDequeue(out var f))
            result.Add(f);
        return result;
    }

    public void Dispose()
    {
        _stopping = true;
        foreach (var t in _threads)
            t.Join(TimeSpan.FromSeconds(2)); // captures wake up at least every 500 ms
    }

    /// <summary>What each gateway's MAC should be: the pin if there is one, else the ARP table.</summary>
    internal static Dictionary<IPAddress, ExpectedMac?> ExpectedGatewayMacs(Snapshot s, NetInterface iface, PinStore pins)
    {
        var result = new Dictionary<IPAddress, ExpectedMac?>();
        foreach (var gw in iface.Gateways)
        {
            var pin = pins.Find(gw);
            var entry = s.Find(iface.Index, gw);
            result[gw] =
                pin is not null ? new ExpectedMac(pin.Mac, MacSource.Pinned) :
                entry is { IsStatic: true, HasMac: true } ? new ExpectedMac(entry.Mac, MacSource.Pinned) :
                entry is { HasMac: true } ? new ExpectedMac(entry.Mac, MacSource.ArpTable) :
                null;
        }
        return result;
    }

    private void Run(NetInterface iface, PcapCapture capture, PacketInspector inspector)
    {
        using (capture)
        {
            var buffer = new byte[PcapCapture.SnapLength];
            while (!_stopping)
            {
                switch (capture.Next(buffer, out int length, out string? error))
                {
                    case CaptureResult.Packet:
                        if (inspector.Inspect(buffer.AsSpan(0, length)) is { } finding)
                            _findings.Enqueue(finding);
                        break;
                    case CaptureResult.Error:
                        if (!_stopping)
                            _findings.Enqueue(new(Severity.Warning,
                                $"Stopped checking packets on {iface.Name}: {error}. Restart watching to try again."));
                        return;
                }
            }
        }
    }
}
