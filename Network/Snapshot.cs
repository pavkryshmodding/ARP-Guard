using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ArpGuard;

internal sealed record NetInterface(
    int Index, string Name, IPAddress? Address, IPAddress? Mask, IReadOnlyList<IPAddress> Gateways)
{
    public bool Contains(IPAddress ip) =>
        Address is not null && Mask is not null && IpUtil.SameSubnet(Address, ip, Mask);

    public string Describe()
    {
        string addr = Address is null ? "" : $"  {Address}/{IpUtil.PrefixLength(Mask!)}";
        string gw = Gateways.Count == 0 ? "" : $"  gateway {string.Join(", ", Gateways)}";
        return $"{Name} (interface {Index}){addr}{gw}";
    }
}

/// <summary>The ARP table plus the active network interfaces, captured at one moment.</summary>
internal sealed class Snapshot
{
    private Snapshot(IReadOnlyList<ArpEntry> entries, IReadOnlyList<NetInterface> interfaces)
    {
        Entries = entries;
        Interfaces = interfaces;
    }

    public IReadOnlyList<ArpEntry> Entries { get; }
    public IReadOnlyList<NetInterface> Interfaces { get; }

    /// <param name="probeGateways">
    /// Ping each gateway first so it's guaranteed to be in the ARP table. Even if the ping
    /// itself is blocked, sending it forces Windows to resolve the gateway's MAC.
    /// </param>
    public static Snapshot Take(bool probeGateways)
    {
        var interfaces = GetActiveInterfaces();
        if (probeGateways)
        {
            foreach (var gw in interfaces.SelectMany(i => i.Gateways))
            {
                try
                {
                    using var ping = new Ping();
                    ping.Send(gw, 800);
                }
                catch (PingException) { }
            }
        }
        return new Snapshot(IpHelper.GetIPv4Neighbors(), interfaces);
    }

    public NetInterface? InterfaceFor(int index) => Interfaces.FirstOrDefault(i => i.Index == index);

    public string InterfaceName(int index) => InterfaceFor(index)?.Name ?? $"interface {index}";

    public bool IsGateway(ArpEntry e) =>
        InterfaceFor(e.InterfaceIndex)?.Gateways.Contains(e.Ip) == true;

    public ArpEntry? Find(int interfaceIndex, IPAddress ip) =>
        Entries.FirstOrDefault(e => e.InterfaceIndex == interfaceIndex && e.Ip.Equals(ip));

    /// <summary>Resolved unicast entries on interfaces that are currently up.</summary>
    public IEnumerable<ArpEntry> ActiveHosts() =>
        Entries.Where(e => e.IsUsable && InterfaceFor(e.InterfaceIndex) is not null);

    private static List<NetInterface> GetActiveInterfaces()
    {
        var result = new List<NetInterface>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up ||
                ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                continue;

            var props = ni.GetIPProperties();
            IPv4InterfaceProperties? v4;
            try { v4 = props.GetIPv4Properties(); }
            catch (NetworkInformationException) { continue; }
            if (v4 is null)
                continue;

            var unicast = props.UnicastAddresses
                .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork);
            var gateways = props.GatewayAddresses
                .Select(g => g.Address)
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any))
                .ToList();

            result.Add(new NetInterface(v4.Index, ni.Name, unicast?.Address, unicast?.IPv4Mask, gateways));
        }
        return result;
    }
}
