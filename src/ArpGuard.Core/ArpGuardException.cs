namespace ArpGuard;

/// <summary>An error meant to be shown to the user as a plain message (no stack trace).</summary>
public sealed class ArpGuardException(string message) : Exception(message);
