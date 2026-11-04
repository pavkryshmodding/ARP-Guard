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

Requires the .NET 10 SDK.

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
- **Start watching** checks every 2 seconds. You can minimize the window: suspicious
  changes play a sound and show a Windows notification.

## The command-line tool

```powershell
dotnet run --project src/ArpGuard.Cli -- list
dotnet run --project src/ArpGuard.Cli -- check --online
# pin/unpin need an elevated (Administrator) terminal:
dotnet run --project src/ArpGuard.Cli -- pin
dotnet run --project src/ArpGuard.Cli -- unpin
dotnet run --project src/ArpGuard.Cli -- watch --log arp-alerts.log
```

| Command | What it does |
|---|---|
| `list`  | ARP table per interface, flagging the gateway, duplicate MACs and randomized MACs |
| `check` | Looks for spoofing signs; `--online` also looks up the gateway's vendor |
| `pin`   | Adds a persistent static entry (defaults to the gateway) after a safety check |
| `unpin` | Removes a static entry; `--all` removes everything ArpGuard pinned |
| `watch` | Polls the table and alerts on MAC changes and new duplicate MACs |

Run `arpguard help` for every option.

## How the checks work

- **Duplicate MAC:** if the gateway's MAC also belongs to another IP, some device is
  answering ARP requests for your router. That's the classic spoofing pattern.
- **Locally administered MAC:** routers normally have a manufacturer-assigned MAC. A
  software-assigned (randomized) one on the gateway is suspicious.
- **Pin mismatch:** the gateway's MAC no longer matches what you pinned.
- **Watch mode:** remembers each IP's MAC and alerts when one changes. A change on the
  gateway or a pinned device counts as critical.

## Limitations

- A static entry protects **this computer only**, and only in one direction. An attacker
  can still poison the *router's* table to intercept traffic going back to you. Full
  protection needs static entries on the router too (or switch features like Dynamic ARP
  Inspection).
- Pinning while you're already being spoofed would pin the attacker. `pin` refuses when
  it sees clear signs of that, but it can't catch everything. Verify the router's MAC
  (printed on its label or shown in its admin page) when in doubt.
- If you replace your router, run `arpguard unpin` or you'll lose your connection.
- Pinned entries are recorded in `%ProgramData%\ArpGuard\pins.json`.

## License

[MIT](LICENSE)
