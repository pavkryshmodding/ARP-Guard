using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace ArpGuard;

/// <summary>Mirrors Windows' NL_NEIGHBOR_STATE.</summary>
public enum NeighborState
{
    Unreachable = 0,
    Incomplete = 1,
    Probe = 2,
    Delay = 3,
    Stale = 4,
    Reachable = 5,
    Permanent = 6,
}

public sealed record ArpEntry(IPAddress Ip, string Mac, int InterfaceIndex, NeighborState State)
{
    public bool HasMac => Mac.Length > 0 && !MacUtil.IsZero(Mac);
    public bool IsStatic => State == NeighborState.Permanent;

    /// <summary>A resolved unicast host - the kind of entry spoofing targets.</summary>
    public bool IsUsable => HasMac && !MacUtil.IsMulticastOrBroadcast(Mac) && IpUtil.IsUnicast(Ip);
}

/// <summary>Reads the IPv4 neighbor (ARP) table through the IP Helper API.</summary>
public static class IpHelper
{
    private const ushort AF_INET = 2;

    // Layout of MIB_IPNET_ROW2 (x86 and x64 are identical):
    //   0  SOCKADDR_INET Address (28 bytes; for IPv4: family @0, port @2, addr @4)
    //  28  ULONG  InterfaceIndex
    //  32  NET_LUID InterfaceLuid (8)
    //  40  UCHAR  PhysicalAddress[32]
    //  72  ULONG  PhysicalAddressLength
    //  76  NL_NEIGHBOR_STATE State
    //  80  UCHAR  Flags (+3 padding)
    //  84  ULONG  ReachabilityTime
    private const int RowSize = 88;
    private const int TableHeaderSize = 8; // ULONG NumEntries, padded to 8-byte alignment

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpNetTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll")]
    private static extern void FreeMibTable(IntPtr memory);

    public static List<ArpEntry> GetIPv4Neighbors()
    {
        int error = GetIpNetTable2(AF_INET, out IntPtr table);
        if (error != 0)
            throw new ArpGuardException($"Couldn't read the ARP table: {new Win32Exception(error).Message}");

        try
        {
            int count = Marshal.ReadInt32(table);
            var entries = new List<ArpEntry>(count);
            for (int i = 0; i < count; i++)
            {
                IntPtr row = table + TableHeaderSize + i * RowSize;
                if ((ushort)Marshal.ReadInt16(row) != AF_INET)
                    continue;

                var ipBytes = new byte[4];
                Marshal.Copy(row + 4, ipBytes, 0, 4);

                int macLength = Math.Clamp(Marshal.ReadInt32(row + 72), 0, 32);
                var macBytes = new byte[macLength];
                Marshal.Copy(row + 40, macBytes, 0, macLength);

                entries.Add(new ArpEntry(
                    new IPAddress(ipBytes),
                    MacUtil.Format(macBytes),
                    Marshal.ReadInt32(row + 28),
                    (NeighborState)Marshal.ReadInt32(row + 76)));
            }
            return entries;
        }
        finally
        {
            FreeMibTable(table);
        }
    }
}
