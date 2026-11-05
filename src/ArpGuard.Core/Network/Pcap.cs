using System.Runtime.InteropServices;
using System.Text;

namespace ArpGuard;

public enum CaptureResult { Packet, Timeout, Error }

/// <summary>
/// A live capture on one adapter through Npcap's wpcap.dll (https://npcap.com).
/// Only the handful of libpcap calls ArpGuard needs are bound.
/// </summary>
public sealed class PcapCapture : IDisposable
{
    private const string Lib = "wpcap.dll";
    private const int ErrbufSize = 256;
    private const uint NetmaskUnknown = 0xffffffff;
    private const int ReadTimeoutMs = 500;
    // Covers Ethernet + ARP, or Ethernet + an IPv4 header with options. Nothing past the headers is kept.
    public const int SnapLength = 128;

    private static readonly Lazy<bool> ResolverInstalled = new(() =>
    {
        NativeLibrary.SetDllImportResolver(typeof(PcapCapture).Assembly, Resolve);
        return true;
    });

    private IntPtr _handle;
    private IntPtr _dumper;

    private PcapCapture(IntPtr handle) => _handle = handle;

    /// <summary>The Npcap version string, or null if Npcap isn't installed.</summary>
    public static string? Version()
    {
        _ = ResolverInstalled.Value;
        try
        {
            return Marshal.PtrToStringAnsi(pcap_lib_version());
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return null;
        }
    }

    /// <param name="adapterId">The adapter GUID, as in <see cref="NetInterface.Id"/>.</param>
    /// <param name="filter">A BPF filter, so the driver only hands over packets we inspect.</param>
    public static PcapCapture Open(string adapterId, string filter)
    {
        _ = ResolverInstalled.Value;
        var errbuf = new byte[ErrbufSize];
        IntPtr handle = pcap_open_live($@"\Device\NPF_{adapterId}", SnapLength, 0, ReadTimeoutMs, errbuf);
        if (handle == IntPtr.Zero)
            throw new ArpGuardException(
                $"Npcap couldn't open the adapter: {CString(errbuf)}. If Npcap was installed with " +
                "\"Restrict Npcap driver's access to Administrators only\", run ArpGuard as administrator.");

        var capture = new PcapCapture(handle);
        try
        {
            capture.SetFilter(filter);
        }
        catch
        {
            capture.Dispose();
            throw;
        }
        return capture;
    }

    /// <summary>Also writes every captured packet to a .pcap file (readable by Wireshark).</summary>
    public void SaveTo(string path)
    {
        if (_dumper != IntPtr.Zero)
            throw new InvalidOperationException("Already saving this capture.");
        _dumper = pcap_dump_open(_handle, path);
        if (_dumper == IntPtr.Zero)
            throw new ArpGuardException($"Npcap couldn't create {path}: {LastError()}");
    }

    /// <summary>
    /// Waits up to half a second for a packet and copies its captured bytes into <paramref name="buffer"/>.
    /// </summary>
    public CaptureResult Next(byte[] buffer, out int length, out string? error)
    {
        length = 0;
        error = null;
        int result = pcap_next_ex(_handle, out IntPtr header, out IntPtr data);
        if (result == 0)
            return CaptureResult.Timeout;
        if (result != 1)
        {
            error = result == -1 ? LastError() : "the capture ended";
            return CaptureResult.Error;
        }

        // struct pcap_pkthdr { struct timeval ts (two 32-bit longs on Windows); bpf_u_int32 caplen; bpf_u_int32 len; }
        if (_dumper != IntPtr.Zero)
            pcap_dump(_dumper, header, data);
        length = Math.Min(Marshal.ReadInt32(header, 8), buffer.Length);
        Marshal.Copy(data, buffer, 0, length);
        return CaptureResult.Packet;
    }

    public void Dispose()
    {
        if (_dumper != IntPtr.Zero)
        {
            pcap_dump_close(_dumper);
            _dumper = IntPtr.Zero;
        }
        if (_handle == IntPtr.Zero)
            return;
        pcap_close(_handle);
        _handle = IntPtr.Zero;
    }

    private void SetFilter(string filter)
    {
        // struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; } - 16 bytes on x64.
        IntPtr program = Marshal.AllocHGlobal(16);
        try
        {
            if (pcap_compile(_handle, program, filter, 1, NetmaskUnknown) != 0)
                throw new ArpGuardException($"Npcap rejected the capture filter '{filter}': {LastError()}");
            try
            {
                if (pcap_setfilter(_handle, program) != 0)
                    throw new ArpGuardException($"Npcap couldn't apply the capture filter: {LastError()}");
            }
            finally
            {
                pcap_freecode(program);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(program);
        }
    }

    private string LastError() => Marshal.PtrToStringAnsi(pcap_geterr(_handle)) ?? "unknown error";

    private static string CString(byte[] buffer)
    {
        int end = Array.IndexOf(buffer, (byte)0);
        return Encoding.ASCII.GetString(buffer, 0, end < 0 ? buffer.Length : end).Trim();
    }

    /// <summary>
    /// Npcap installs into System32\Npcap, which isn't on the normal DLL search path
    /// (unless it was installed in "WinPcap compatible mode").
    /// </summary>
    private static IntPtr Resolve(string name, System.Reflection.Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!name.Equals(Lib, StringComparison.OrdinalIgnoreCase))
            return IntPtr.Zero;

        string dir = Path.Combine(Environment.SystemDirectory, "Npcap");
        string path = Path.Combine(dir, Lib);
        if (File.Exists(path))
        {
            SetDllDirectory(dir); // wpcap.dll loads Packet.dll from the same folder
            if (NativeLibrary.TryLoad(path, out IntPtr handle))
                return handle;
        }
        return IntPtr.Zero; // fall back to the default search
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetDllDirectory(string path);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr pcap_lib_version();

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int toMs, byte[] errbuf);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern int pcap_compile(IntPtr p, IntPtr program, string filter, int optimize, uint netmask);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pcap_setfilter(IntPtr p, IntPtr program);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_freecode(IntPtr program);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pcap_next_ex(IntPtr p, out IntPtr header, out IntPtr data);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr pcap_geterr(IntPtr p);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_close(IntPtr p);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr pcap_dump_open(IntPtr p, string path);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_dump(IntPtr dumper, IntPtr header, IntPtr data);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_dump_close(IntPtr dumper);
}
