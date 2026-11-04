using System.Net;

namespace ArpGuard;

/// <summary>Works out which interface + IP a pin/unpin command is about.</summary>
internal static class Target
{
    public static (NetInterface Interface, IPAddress Ip) Resolve(Snapshot s, CliArgs cli)
    {
        var ip = cli.GetIp("ip");
        NetInterface? iface = null;

        if (cli.GetInterfaceIndex() is int index)
        {
            iface = s.InterfaceFor(index)
                ?? throw new ArpGuardException($"No active interface number {index}. Run 'arpguard list' to see them.");
        }

        if (ip is null)
        {
            var candidates = (iface is null ? s.Interfaces : [iface]).Where(i => i.Gateways.Count > 0).ToList();
            if (candidates.Count == 0)
                throw new ArpGuardException("No default gateway found. Pass --ip to choose an address.");
            if (candidates.Count > 1)
                throw new ArpGuardException(
                    "Several interfaces have a gateway. Choose one with --interface <number>:" + Environment.NewLine +
                    string.Join(Environment.NewLine, candidates.Select(c => "  " + c.Describe())));
            return (candidates[0], candidates[0].Gateways[0]);
        }

        iface ??= s.Interfaces.FirstOrDefault(i => i.Contains(ip))
            ?? throw new ArpGuardException($"{ip} isn't on any active interface's subnet. Pass --interface <number>.");
        return (iface, ip);
    }
}
