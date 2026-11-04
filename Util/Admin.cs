using System.Security.Principal;

namespace ArpGuard;

internal static class Admin
{
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static void Require(string command)
    {
        if (!IsElevated())
            throw new CliException(
                $"'{command}' changes the system ARP table and needs administrator rights. " +
                "Re-run it from an elevated terminal (right-click Terminal -> Run as administrator).");
    }
}
