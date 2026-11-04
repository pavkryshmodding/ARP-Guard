using System.Net;

namespace ArpGuard;

/// <summary>
/// Looks up who manufactured a network card from the first 3 bytes of its MAC (the OUI).
/// Only the OUI is sent, never the full MAC.
/// </summary>
public static class VendorLookup
{
    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("ArpGuard/1.0");
        return client;
    }

    /// <returns>The vendor name, "unknown vendor", or null if the lookup failed.</returns>
    public static async Task<string?> LookupAsync(string mac)
    {
        string oui = mac[..8].ToUpperInvariant();
        try
        {
            using var response = await Http.GetAsync($"https://api.macvendors.com/{oui}");
            if (response.StatusCode == HttpStatusCode.NotFound)
                return "unknown vendor";
            if (!response.IsSuccessStatusCode)
                return null;
            return (await response.Content.ReadAsStringAsync()).Trim();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return null;
        }
    }
}
