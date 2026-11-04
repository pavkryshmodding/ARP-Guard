using System.Net;
using System.Text.Json;

namespace ArpGuard;

internal sealed record PinRecord(string Ip, string Mac, int InterfaceIndex, string InterfaceName, DateTimeOffset PinnedAt);

/// <summary>
/// Remembers which entries ArpGuard pinned, so 'unpin --all' only touches ours and
/// 'check'/'watch' can tell when a gateway no longer matches its pin.
/// Stored in %ProgramData%\ArpGuard\pins.json.
/// </summary>
internal sealed class PinStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ArpGuard", "pins.json");

    private PinStore(List<PinRecord> pins) => Pins = pins;

    public List<PinRecord> Pins { get; }

    public static PinStore Load()
    {
        try
        {
            if (!File.Exists(FilePath))
                return new PinStore([]);
            var pins = JsonSerializer.Deserialize<List<PinRecord>>(File.ReadAllText(FilePath), JsonOptions);
            return new PinStore(pins ?? []);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            Ui.Warn($"Couldn't read {FilePath} ({ex.Message}); continuing without saved pins.");
            return new PinStore([]);
        }
    }

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(Pins, JsonOptions));
    }

    public PinRecord? Find(IPAddress ip) => Pins.FirstOrDefault(p => p.Ip == ip.ToString());

    public void Upsert(PinRecord record)
    {
        Remove(IPAddress.Parse(record.Ip));
        Pins.Add(record);
    }

    public void Remove(IPAddress ip) => Pins.RemoveAll(p => p.Ip == ip.ToString());
}
