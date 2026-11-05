using System.Net;
using System.Numerics;

namespace ArpGuard;

public static class MacUtil
{
    /// <summary>Formats as "aa-bb-cc-dd-ee-ff" (the format netsh expects). Empty for no address.</summary>
    public static string Format(byte[] bytes) =>
        string.Join("-", bytes.Select(b => b.ToString("x2")));

    public static bool IsZero(string mac) => mac.All(c => c is '0' or '-');

    private static byte FirstByte(string mac) => Convert.ToByte(mac[..2], 16);

    /// <summary>Group bit set: multicast or broadcast (ff-ff-ff-ff-ff-ff), never a real host.</summary>
    public static bool IsMulticastOrBroadcast(string mac) => (FirstByte(mac) & 0x01) != 0;

    /// <summary>
    /// Locally administered bit set: the MAC was assigned by software (e.g. Wi-Fi MAC randomization)
    /// rather than burned in by a manufacturer.
    /// </summary>
    public static bool IsLocallyAdministered(string mac) => (FirstByte(mac) & 0x02) != 0;

    /// <summary>
    /// True for two MACs that are almost certainly one device's different interfaces. A router owns a
    /// block of consecutive MACs (LAN, WAN, each Wi-Fi radio) and may send traffic from any of them;
    /// guest/mesh networks often reuse the MAC with the locally administered bit set.
    /// An attacker could forge a MAC like this, but tools like parental-control boxes use their own.
    /// </summary>
    public static bool IsSibling(string a, string b)
    {
        if (a == b || a.Length != 17 || b.Length != 17)
            return a == b;
        bool sameMiddle = a[2..14] == b[2..14];
        bool firstMatches = (FirstByte(a) | 0x02) == (FirstByte(b) | 0x02);
        int lastDiff = Math.Abs(Convert.ToByte(a[15..], 16) - Convert.ToByte(b[15..], 16));
        return sameMiddle && firstMatches && lastDiff <= 15;
    }

    /// <summary>Accepts aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabb.ccdd.eeff or aabbccddeeff.</summary>
    public static bool TryNormalize(string input, out string mac)
    {
        string hex = new(input.Where(c => c is not (':' or '-' or '.')).ToArray());
        mac = "";
        if (hex.Length != 12 || !hex.All(Uri.IsHexDigit))
            return false;
        mac = string.Join("-", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2).ToLowerInvariant()));
        return true;
    }
}

public static class IpUtil
{
    public static uint ToUInt32(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
    }

    /// <summary>Excludes 0.x.x.x, multicast (224+) and reserved/broadcast (240+).</summary>
    public static bool IsUnicast(IPAddress ip)
    {
        byte first = ip.GetAddressBytes()[0];
        return first != 0 && first < 224;
    }

    public static bool SameSubnet(IPAddress a, IPAddress b, IPAddress mask)
    {
        uint m = ToUInt32(mask);
        return (ToUInt32(a) & m) == (ToUInt32(b) & m);
    }

    public static int PrefixLength(IPAddress mask) => BitOperations.PopCount(ToUInt32(mask));
}
