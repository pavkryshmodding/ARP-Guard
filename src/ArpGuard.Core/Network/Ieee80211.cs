namespace ArpGuard;

/// <summary>
/// Turns 802.11 (Wi-Fi) data frames into the Ethernet frames they carry. pktmon logs Wi-Fi
/// traffic as raw 802.11 frames but labels them as Ethernet, so the pcapng reader checks
/// every frame with <see cref="TryToEthernet"/>.
/// </summary>
public static class Ieee80211
{
    private static ReadOnlySpan<byte> SnapHeader => [0xAA, 0xAA, 0x03];

    /// <summary>
    /// Converts an unencrypted 802.11 data frame (as the Wi-Fi card hands it over, already decrypted)
    /// to Ethernet: destination and source are the frame's real endpoints, not the access point.
    /// </summary>
    /// <returns>Null if this isn't an 802.11 data frame carrying an LLC/SNAP payload.</returns>
    public static byte[]? TryToEthernet(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 24)
            return null;
        byte fc0 = frame[0], fc1 = frame[1];
        if ((fc0 & 0x03) != 0 || (fc0 & 0x0C) != 0x08)
            return null; // not protocol version 0, or not a data frame
        int subtype = fc0 >> 4;
        if ((subtype & 0x04) != 0)
            return null; // null-data variants carry no payload

        bool toDs = (fc1 & 0x01) != 0, fromDs = (fc1 & 0x02) != 0;
        bool qos = (subtype & 0x08) != 0;
        bool order = (fc1 & 0x80) != 0;
        int header = 24 + (toDs && fromDs ? 6 : 0) + (qos ? 2 : 0) + (qos && order ? 4 : 0);
        if (frame.Length < header + 8 || !frame.Slice(header, 3).SequenceEqual(SnapHeader))
            return null; // too short, encrypted, or not SNAP-encapsulated

        // Address 1-4 are at offsets 4, 10, 16, 24. Which is which depends on the To/From DS bits.
        var (dst, src) = (toDs, fromDs) switch
        {
            (false, false) => (4, 10),
            (true, false) => (16, 10), // station -> access point
            (false, true) => (4, 16),  // access point -> station
            (true, true) => (16, 24),  // mesh / WDS
        };

        var payload = frame[(header + 6)..]; // EtherType followed by the packet
        var ethernet = new byte[12 + payload.Length];
        frame.Slice(dst, 6).CopyTo(ethernet);
        frame.Slice(src, 6).CopyTo(ethernet.AsSpan(6));
        payload.CopyTo(ethernet.AsSpan(12));
        return ethernet;
    }
}
