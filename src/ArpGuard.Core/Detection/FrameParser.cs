using System.Buffers.Binary;
using System.Net;

namespace ArpGuard;

public enum FrameKind { Other, Arp, IPv4 }

/// <summary>The parts of an Ethernet frame ArpGuard looks at. ARP/IP fields are null when they don't apply.</summary>
public sealed record ParsedFrame(
    FrameKind Kind,
    string DstMac,
    string SrcMac,
    ushort ArpOp = 0,
    string? ArpSenderMac = null,
    IPAddress? ArpSenderIp = null,
    IPAddress? IpSource = null)
{
    public string ArpKind => ArpOp switch { 1 => "an ARP request", 2 => "an ARP reply", _ => "an ARP packet" };
}

public static class FrameParser
{
    private const ushort EtherTypeIPv4 = 0x0800;
    private const ushort EtherTypeArp = 0x0806;
    private const ushort EtherTypeVlan = 0x8100;

    /// <returns>Null if the frame is too short to be Ethernet.</returns>
    public static ParsedFrame? Parse(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 14)
            return null;
        string dst = MacUtil.Format(frame[..6].ToArray());
        string src = MacUtil.Format(frame[6..12].ToArray());
        ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[12..]);
        var payload = frame[14..];
        if (etherType == EtherTypeVlan && payload.Length >= 4)
        {
            etherType = BinaryPrimitives.ReadUInt16BigEndian(payload[2..]);
            payload = payload[4..];
        }

        // ARP: htype(2) ptype(2) hlen(1) plen(1) op(2) sha(6) spa(4) tha(6) tpa(4)
        if (etherType == EtherTypeArp && payload.Length >= 28 &&
            BinaryPrimitives.ReadUInt16BigEndian(payload) == 1 &&
            BinaryPrimitives.ReadUInt16BigEndian(payload[2..]) == EtherTypeIPv4 &&
            payload[4] == 6 && payload[5] == 4)
        {
            return new(FrameKind.Arp, dst, src,
                ArpOp: BinaryPrimitives.ReadUInt16BigEndian(payload[6..]),
                ArpSenderMac: MacUtil.Format(payload[8..14].ToArray()),
                ArpSenderIp: new IPAddress(payload[14..18]));
        }

        if (etherType == EtherTypeIPv4 && payload.Length >= 20 && payload[0] >> 4 == 4)
            return new(FrameKind.IPv4, dst, src, IpSource: new IPAddress(payload[12..16]));

        return new(FrameKind.Other, dst, src);
    }
}
