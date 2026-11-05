using System.Diagnostics;

namespace ArpGuard;

internal static class ProcessRunner
{
    /// <summary>Runs a console program without a window and returns its exit code and combined output.</summary>
    public static (int ExitCode, string Output) Run(string fileName, string arguments)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var process = Process.Start(psi) ?? throw new ArpGuardException($"Couldn't start {fileName}.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        return (process.ExitCode, stdout.Result + stderr.Result);
    }
}
