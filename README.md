# ArpGuard

A small Windows command-line tool that inspects your ARP table, looks for signs of ARP
spoofing, pins static ARP entries (usually your router), and watches for suspicious changes.

## Build & run

Requires the .NET 10 SDK.

```powershell
dotnet build
dotnet run -- list
dotnet run -- check --online
# pin/unpin need an elevated (Administrator) terminal:
dotnet run -- pin
dotnet run -- unpin
dotnet run -- watch --log arp-alerts.log
```

To produce a single `arpguard.exe`:

```powershell
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
```

## Commands

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
