using System.Net;
using System.Net.Sockets;

namespace ArpGuard;

/// <summary>An error that should be shown to the user as a plain message (no stack trace).</summary>
internal sealed class CliException(string message) : Exception(message);

/// <summary>Minimal parser for "command --flag --option value --option=value".</summary>
internal sealed class CliArgs
{
    private readonly Dictionary<string, string?> _options;

    private CliArgs(string command, Dictionary<string, string?> options)
    {
        Command = command;
        _options = options;
    }

    public string Command { get; }

    public static CliArgs Parse(string[] argv)
    {
        if (argv.Length == 0)
            return new CliArgs("help", new());

        var options = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < argv.Length; i++)
        {
            string token = argv[i];
            if (!token.StartsWith("--") || token.Length == 2)
                throw new CliException($"Unexpected argument '{token}'. Options look like --name or --name value.");

            string name = token[2..];
            string? value = null;
            int eq = name.IndexOf('=');
            if (eq >= 0)
            {
                value = name[(eq + 1)..];
                name = name[..eq];
            }
            else if (i + 1 < argv.Length && !argv[i + 1].StartsWith("--"))
            {
                value = argv[++i];
            }
            options[name] = value;
        }
        return new CliArgs(argv[0].ToLowerInvariant(), options);
    }

    /// <summary>Rejects options the current command doesn't understand.</summary>
    public void Allow(params string[] names)
    {
        foreach (string key in _options.Keys)
        {
            if (!names.Contains(key, StringComparer.OrdinalIgnoreCase))
                throw new CliException($"'{Command}' doesn't take --{key}. Run 'arpguard help' for usage.");
        }
    }

    public bool Flag(string name)
    {
        if (!_options.TryGetValue(name, out string? value))
            return false;
        if (value is not null)
            throw new CliException($"--{name} is a flag and doesn't take a value (got '{value}').");
        return true;
    }

    public string? Get(string name)
    {
        if (!_options.TryGetValue(name, out string? value))
            return null;
        return value ?? throw new CliException($"--{name} needs a value.");
    }

    public int GetInt(string name, int fallback, int min, int max)
    {
        string? text = Get(name);
        if (text is null)
            return fallback;
        if (!int.TryParse(text, out int n) || n < min || n > max)
            throw new CliException($"--{name} must be a whole number between {min} and {max}.");
        return n;
    }

    public int? GetInterfaceIndex()
    {
        string? text = Get("interface");
        if (text is null)
            return null;
        if (!int.TryParse(text, out int n) || n <= 0)
            throw new CliException("--interface must be an interface number as shown by 'arpguard list' (e.g. 12).");
        return n;
    }

    public IPAddress? GetIp(string name)
    {
        string? text = Get(name);
        if (text is null)
            return null;
        if (!IPAddress.TryParse(text, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || text.Count(c => c == '.') != 3)
            throw new CliException($"--{name}: '{text}' isn't a valid IPv4 address.");
        return ip;
    }
}
