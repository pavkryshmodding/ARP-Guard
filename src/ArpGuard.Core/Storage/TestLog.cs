using System.Text;

namespace ArpGuard;

/// <summary>
/// Saves each capture test as a text report (plus its raw capture) in %ProgramData%\ArpGuard\tests,
/// so results can be compared or analysed later. Keeps the newest <see cref="KeepRuns"/> runs.
/// </summary>
public static class TestLog
{
    public const int KeepRuns = 50;

    public static string Folder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ArpGuard", "tests");

    /// <summary>
    /// Creates the folder and returns the path (without extension) every file of this run starts with,
    /// e.g. ...\tests\2026-11-05_08-15-30_npcap.
    /// </summary>
    public static string NewRun(string method, DateTime started)
    {
        Directory.CreateDirectory(Folder);
        return Path.Combine(Folder, $"{started:yyyy-MM-dd_HH-mm-ss}_{method.ToLowerInvariant()}");
    }

    /// <summary>Writes "{run}.txt" for a finished, failed or cancelled test, then prunes old runs.</summary>
    /// <param name="outcome">"ok", "danger", "cancelled" or "error".</param>
    /// <returns>The report's path.</returns>
    public static string Write(
        string run, string method, DateTime started, TimeSpan duration, Snapshot? snapshot, PinStore pins,
        CaptureTestResult? result, string outcome, string? error = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ArpGuard capture test");
        sb.AppendLine($"Method:    {method}");
        sb.AppendLine($"Started:   {started:yyyy-MM-dd HH:mm:ss zzz}");
        sb.AppendLine($"Length:    {duration.TotalSeconds:0} s (pinging 1.1.1.1 once a second)");
        sb.AppendLine($"Outcome:   {outcome.ToUpperInvariant()}");
        if (error is not null)
            sb.AppendLine($"Error:     {error}");
        sb.AppendLine($"Npcap:     {PcapCapture.Version() ?? "not installed"}");
        sb.AppendLine($"Windows:   {Environment.OSVersion.VersionString}");
        sb.AppendLine($"ArpGuard:  {typeof(TestLog).Assembly.GetName().Version}");

        sb.AppendLine();
        sb.AppendLine("== Pins ==");
        if (pins.Pins.Count == 0)
            sb.AppendLine("(none)");
        foreach (var p in pins.Pins)
            sb.AppendLine($"{p.Ip} -> {p.Mac} on {p.InterfaceName} (interface {p.InterfaceIndex}), pinned {p.PinnedAt:yyyy-MM-dd HH:mm}");

        if (snapshot is not null)
        {
            sb.AppendLine();
            sb.AppendLine("== Interfaces at start ==");
            foreach (var i in snapshot.Interfaces)
                sb.AppendLine($"{i.Describe()}  mac {(i.Mac.Length > 0 ? i.Mac : "none")}  id {i.Id}");

            sb.AppendLine();
            sb.AppendLine("== ARP table at start ==");
            foreach (var e in snapshot.ActiveHosts().OrderBy(e => e.InterfaceIndex).ThenBy(e => IpUtil.ToUInt32(e.Ip)))
            {
                string notes = EntryText.Notes(e, snapshot, EntryText.DuplicateMacs(snapshot));
                sb.AppendLine($"{e.Ip,-16} {e.Mac}  {EntryText.State(e),-16} interface {e.InterfaceIndex}  {notes}".TrimEnd());
            }
        }

        if (result is not null)
        {
            sb.AppendLine();
            sb.AppendLine("== Traffic ==");
            foreach (string line in result.Report)
                sb.AppendLine(line);

            sb.AppendLine();
            sb.AppendLine("== Findings ==");
            if (result.Findings.Count == 0)
                sb.AppendLine("(none)");
            foreach (var f in result.Findings)
                sb.AppendLine($"{f.Severity.ToString().ToUpperInvariant(),-7} {f.Message}");

            sb.AppendLine();
            sb.AppendLine("== Raw captures (packet headers only) ==");
            if (result.CaptureFiles.Count == 0)
                sb.AppendLine("(none saved)");
            foreach (string file in result.CaptureFiles)
                sb.AppendLine(file);
        }

        string path = run + ".txt";
        File.WriteAllText(path, sb.ToString());
        Prune();
        return path;
    }

    /// <summary>Deletes all files of runs older than the newest <see cref="KeepRuns"/>.</summary>
    private static void Prune()
    {
        try
        {
            var runs = Directory.GetFiles(Folder, "*.txt")
                .Select(Path.GetFileNameWithoutExtension)
                .OfType<string>()
                .OrderDescending() // names start with a sortable timestamp
                .Skip(KeepRuns);
            foreach (string run in runs)
                foreach (string file in Directory.GetFiles(Folder, run + "*"))
                    File.Delete(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
