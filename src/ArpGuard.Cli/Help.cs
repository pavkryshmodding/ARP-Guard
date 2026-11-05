namespace ArpGuard;

internal static class Help
{
    public static int Print()
    {
        Console.WriteLine("""
            ArpGuard - inspect and protect your ARP table against spoofing (Windows)

            Usage: arpguard <command> [options]

            Commands:
              list                 Show the ARP table, highlighting gateways and duplicate MACs
                --all              Include multicast/broadcast/incomplete entries and inactive interfaces

              check                Look for signs of ARP spoofing
                --online           Also look up the gateway's MAC vendor (sends only the first
                                   3 bytes of the MAC to api.macvendors.com)
                --listen <sec>     Also inspect network traffic for this long (needs Npcap).
                                   Catches spoofing the ARP table can't show

              pin                  Add a static (permanent) ARP entry - defaults to your gateway  [admin]
                --ip <addr>        IP to pin instead of the gateway
                --mac <mac>        MAC to use instead of the one currently in the ARP table
                --interface <n>    Interface number (see 'list') when several have a gateway
                --yes              Don't ask for confirmation
                --force            Pin even if spoofing signs were detected

              unpin                Remove a static entry - defaults to your gateway  [admin]
                --ip <addr>        IP to unpin
                --interface <n>    Only on this interface
                --all              Remove every entry ArpGuard has pinned
                --yes              Don't ask for confirmation

              watch                Monitor the ARP table and alert on suspicious changes
                --interval <sec>   Seconds between checks (default 2)
                --log <file>       Also append alerts to a file
                --no-beep          Don't beep on critical alerts
                --no-capture       Only read the ARP table; don't inspect packets with Npcap

            Exit codes: 0 = ok, 1 = error/cancelled, 2 = 'check' found signs of spoofing
            """);
        return 0;
    }
}
