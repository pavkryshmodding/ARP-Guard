namespace ArpGuard;

/// <summary>Human-readable descriptions of ARP entries, shared by 'list' and the GUI table.</summary>
public static class EntryText
{
    public static string State(ArpEntry e) => e.State switch
    {
        NeighborState.Permanent => "static",
        NeighborState.Reachable => "dynamic",
        NeighborState.Stale => "dynamic (stale)",
        _ => e.State.ToString().ToLowerInvariant(),
    };

    /// <summary>The (interface, MAC) pairs that more than one IP is using.</summary>
    public static HashSet<(int Interface, string Mac)> DuplicateMacs(Snapshot s) =>
        SpoofDetector.FindDuplicates(s).Select(g => (g.InterfaceIndex, g.Mac)).ToHashSet();

    public static string Notes(ArpEntry e, Snapshot s, HashSet<(int Interface, string Mac)> duplicateMacs)
    {
        var notes = new List<string>();
        if (s.IsGateway(e)) notes.Add("GATEWAY");
        if (duplicateMacs.Contains((e.InterfaceIndex, e.Mac))) notes.Add("DUPLICATE MAC");
        if (e.IsUsable && MacUtil.IsLocallyAdministered(e.Mac)) notes.Add("random/local MAC");
        return string.Join(", ", notes);
    }
}
