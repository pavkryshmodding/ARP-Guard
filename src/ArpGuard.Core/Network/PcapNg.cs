using System.Buffers.Binary;

namespace ArpGuard;

/// <summary>Reads the Ethernet frames out of a pcapng file (the format 'pktmon etl2pcap' writes).</summary>
public static class PcapNg
{
    private const uint SectionHeader = 0x0A0D0D0A;
    private const uint InterfaceDescription = 1;
    private const uint SimplePacket = 3;
    private const uint EnhancedPacket = 6;
    private const uint ByteOrderMagic = 0x1A2B3C4D;
    private const ushort LinkTypeEthernet = 1;
    private const ushort LinkTypeIeee80211 = 105;

    /// <returns>
    /// The Ethernet frames; how many packets were skipped (not Ethernet or Wi-Fi data); and how many
    /// were Wi-Fi frames converted to Ethernet.
    /// </returns>
    public static (List<byte[]> Frames, int Skipped, int FromWifi) ReadEthernetFrames(string path)
    {
        byte[] file = File.ReadAllBytes(path);
        var frames = new List<byte[]>();
        var linkTypes = new List<ushort>();
        int skipped = 0, fromWifi = 0;

        void Add(ushort linkType, ReadOnlySpan<byte> data)
        {
            // pktmon labels raw Wi-Fi frames as Ethernet, so check every frame for an 802.11 data header.
            if (linkType is LinkTypeEthernet or LinkTypeIeee80211 && Ieee80211.TryToEthernet(data) is { } converted)
            {
                frames.Add(converted);
                fromWifi++;
            }
            else if (linkType == LinkTypeEthernet)
                frames.Add(data.ToArray());
            else
                skipped++;
        }

        int pos = 0;
        while (pos + 12 <= file.Length)
        {
            uint type = U32(file, pos);
            int length = (int)U32(file, pos + 4);
            if (length < 12 || length % 4 != 0 || pos + length > file.Length)
                throw new ArpGuardException($"{Path.GetFileName(path)} is damaged (bad block at byte {pos}).");
            int body = pos + 8;
            int bodyEnd = pos + length - 4;

            switch (type)
            {
                case SectionHeader:
                    if (U32(file, body) != ByteOrderMagic)
                        throw new ArpGuardException($"{Path.GetFileName(path)} isn't a little-endian pcapng file.");
                    linkTypes.Clear(); // interface IDs restart in each section
                    break;

                case InterfaceDescription:
                    linkTypes.Add(BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(body)));
                    break;

                case EnhancedPacket:
                {
                    int iface = (int)U32(file, body);
                    int captured = (int)U32(file, body + 12);
                    int data = body + 20;
                    if (iface < linkTypes.Count && data + captured <= bodyEnd)
                        Add(linkTypes[iface], file.AsSpan(data, captured));
                    else
                        skipped++;
                    break;
                }

                case SimplePacket:
                {
                    int data = body + 4;
                    int captured = Math.Min((int)U32(file, body), bodyEnd - data);
                    if (linkTypes.Count > 0 && captured > 0)
                        Add(linkTypes[0], file.AsSpan(data, captured));
                    else
                        skipped++;
                    break;
                }
            }
            pos += length;
        }
        return (frames, skipped, fromWifi);
    }

    private static uint U32(byte[] b, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(offset));
}
