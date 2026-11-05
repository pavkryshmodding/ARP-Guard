using System.Net;

namespace ArpGuard;

/// <summary>
/// Writes ARP entries through netsh, which (unlike "arp -s" or the IP Helper API) can store
/// them persistently so they survive a reboot.
/// </summary>
public static class Netsh
{
    public static void AddStaticNeighbor(int interfaceIndex, IPAddress ip, string mac)
    {
        // An existing dynamic entry for the same IP makes "add" fail, so clear it first.
        // It's fine if this fails - that just means there was nothing to delete.
        Run($"interface ipv4 delete neighbors interface={interfaceIndex} address={ip}");

        var (code, output) = Run(
            $"interface ipv4 add neighbors interface={interfaceIndex} address={ip} neighbor={mac} store=persistent");
        if (code != 0)
            throw new ArpGuardException($"netsh couldn't add the entry (exit code {code}): {output.Trim()}");
    }

    public static void DeleteNeighbor(int interfaceIndex, IPAddress ip)
    {
        var (code, output) = Run($"interface ipv4 delete neighbors interface={interfaceIndex} address={ip}");
        if (code != 0)
            throw new ArpGuardException($"netsh couldn't remove the entry (exit code {code}): {output.Trim()}");
    }

    private static (int ExitCode, string Output) Run(string arguments) => ProcessRunner.Run("netsh", arguments);
}
