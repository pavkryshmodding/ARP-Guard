# ArpGuard

A small Windows tool that inspects your ARP table, looks for signs of ARP spoofing, pins
static ARP entries (usually your router), and watches for suspicious changes. It comes as
both a window (`ArpGuardGui.exe`) and a command-line tool (`arpguard.exe`).

## Project layout

| Folder | What's in it |
|---|---|
| `src/ArpGuard.Core` | Shared logic: reading the ARP table, spoofing checks, pinning, watching |
| `src/ArpGuard.Cli`  | The `arpguard` command-line tool |
| `src/ArpGuard.Gui`  | The `ArpGuardGui` window (Windows Forms) |

## Build

Requires the .NET 10 SDK. To check packets as well as the ARP table (recommended), also
install [Npcap](https://npcap.com/#download). ArpGuard works without it, but then it misses
the attacks described under *Packet checks* below.

```powershell
dotnet build
```

To produce standalone `.exe` files in `publish\`:

```powershell
dotnet publish src/ArpGuard.Gui -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish
dotnet publish src/ArpGuard.Cli -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish
```

## The window

Run `src\ArpGuard.Gui\bin\Debug\net10.0-windows\ArpGuardGui.exe` (or the published one).
It asks for administrator rights on start, because pinning changes the system ARP table.

- The coloured bar shows whether your router is pinned, or turns red on signs of spoofing.
- **Pin gateway / Unpin gateway** pins your router's current MAC after a safety check,
  or removes the pin.
- **Check now** re-scans and writes the results to the log.
- **Start watching** checks every 2 seconds and, if Npcap is installed, inspects packets
  as they arrive. You can minimize the window: suspicious changes play a sound and show a
  Windows notification.
- **Test** menu: captures traffic for a set time (**Test length**, default 30 s) while pinging
  1.1.1.1 once a second, then lists every MAC that claimed to be your router or your computer,
  and which MACs delivered your internet traffic.
  - **Npcap capture test** uses Npcap, the same way watching does.
  - **pktmon capture test** uses Windows' built-in `pktmon` instead, so it works without
    Npcap and double-checks it. It won't start if another pktmon capture is already running.

## The command-line tool

```powershell
dotnet run --project src/ArpGuard.Cli -- list
dotnet run --project src/ArpGuard.Cli -- check --online
dotnet run --project src/ArpGuard.Cli -- check --listen 15
# pin/unpin need an elevated (Administrator) terminal:
dotnet run --project src/ArpGuard.Cli -- pin
dotnet run --project src/ArpGuard.Cli -- unpin
dotnet run --project src/ArpGuard.Cli -- watch --log arp-alerts.log
```

| Command | What it does |
|---|---|
| `list`  | ARP table per interface, flagging the gateway, duplicate MACs and randomized MACs |
| `check` | Looks for spoofing signs; `--online` also looks up the gateway's vendor; `--listen <sec>` also inspects packets |
| `pin`   | Adds a persistent static entry (defaults to the gateway) after a safety check |
| `unpin` | Removes a static entry; `--all` removes everything ArpGuard pinned |
| `watch` | Polls the table and alerts on MAC changes and new duplicate MACs, and inspects packets (`--no-capture` to skip) |

Run `arpguard help` for every option.

## How the checks work

- **Duplicate MAC:** if the gateway's MAC also belongs to another IP, some device is
  answering ARP requests for your router. That's the classic spoofing pattern.
- **Locally administered MAC:** routers normally have a manufacturer-assigned MAC. A
  software-assigned (randomized) one on the gateway is suspicious.
- **Pin mismatch:** the gateway's MAC no longer matches what you pinned.
- **Watch mode:** remembers each IP's MAC and alerts when one changes. A change on the
  gateway or a pinned device counts as critical.

### Packet checks (needs Npcap)

The ARP table only shows what Windows *accepted*. Once the gateway is pinned, Windows
silently drops forged replies, so the table looks clean even under attack. And spoofing aimed
at the router (telling it that the attacker is *you*) never touches your table at all. This
is how parental-control boxes like Circle work, and why they keep working after you pin.
With Npcap, ArpGuard reads the packets themselves and flags:

- **A second MAC claiming the gateway's IP** in an ARP packet, even if your pin blocked it.
- **Another MAC claiming this computer's IP:** someone is telling the router to send your
  traffic to them.
- **Internet traffic arriving from a MAC that isn't the router's:** a device is relaying the
  traffic sent back to you.

MACs that differ from the router's only in the last digits (for example its Wi-Fi radio) are
treated as the same router and only noted, since routers own a block of consecutive MACs.

Only packet headers are captured (128 bytes), and only ARP plus traffic from outside your
network addressed to you. Nothing is saved or sent anywhere.

## Limitations

- A static entry protects **this computer only**, and only in one direction. An attacker
  can still poison the *router's* table to intercept or block traffic going back to you.
  ArpGuard can *detect* that (with Npcap) but can't prevent it. Full
  protection needs static entries on the router too (or switch features like Dynamic ARP
  Inspection).
- Pinning while you're already being spoofed would pin the attacker. `pin` refuses when
  it sees clear signs of that, but it can't catch everything. Verify the router's MAC
  (printed on its label or shown in its admin page) when in doubt.
- If you replace your router, run `arpguard unpin` or you'll lose your connection.
- Pinned entries are recorded in `%ProgramData%\ArpGuard\pins.json`.

## License

[MIT](LICENSE)
