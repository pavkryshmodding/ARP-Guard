using System.Media;

namespace ArpGuard;

internal sealed class MainForm : Form
{
    private const int WatchIntervalMs = 2000;

    private readonly Label _status = new();
    private readonly Button _pin = new();
    private readonly Button _check = new();
    private readonly Button _watch = new();
    private readonly ListView _table = new();
    private readonly TextBox _log = new();
    private readonly SplitContainer _split = new();
    private readonly System.Windows.Forms.Timer _timer = new();
    private readonly NotifyIcon _tray = new();
    private readonly MenuStrip _menu = new();
    private readonly ToolStripMenuItem _testNpcap = new("&Npcap capture test");
    private readonly ToolStripMenuItem _testPktmon = new("&pktmon capture test");
    private readonly Font _bold;

    private ArpWatcher? _watcher;
    private bool _ticking;
    private bool _gatewayPinned;
    private bool _alarm; // a danger alert seen while watching; cleared by "Check now"
    private int _testSeconds = 30;
    private CancellationTokenSource? _testCts; // set while a capture test runs
    private bool _closeAfterTest;

    public MainForm()
    {
        Text = "ArpGuard";
        ClientSize = new Size(Px(680), Px(540));
        MinimumSize = new Size(Px(500), Px(420));
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 10f);
        Icon = SystemIcons.Shield;
        _bold = new Font(Font, FontStyle.Bold);

        _status.Dock = DockStyle.Top;
        _status.Height = Px(56);
        _status.TextAlign = ContentAlignment.MiddleCenter;
        _status.Font = new Font("Segoe UI", 14f, FontStyle.Bold);
        _status.ForeColor = Color.White;
        _status.BackColor = Color.Gray;
        _status.Text = "Checking...";

        var buttons = new TableLayoutPanel { Dock = DockStyle.Top, Height = Px(52), ColumnCount = 3 };
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));

        _pin.Dock = DockStyle.Fill;
        _pin.Text = "Pin gateway";
        _pin.Click += async (_, _) => await RunBusyAsync(PinOrUnpinAsync);
        _check.Dock = DockStyle.Fill;
        _check.Text = "Check now";
        _check.Click += async (_, _) => await RunBusyAsync(() => RefreshAsync(writeFindings: true));
        _watch.Dock = DockStyle.Fill;
        _watch.Text = "Start watching";
        _watch.Click += async (_, _) => await ToggleWatchAsync();
        buttons.Controls.Add(_pin, 0, 0);
        buttons.Controls.Add(_check, 1, 0);
        buttons.Controls.Add(_watch, 2, 0);

        _table.Dock = DockStyle.Fill;
        _table.View = View.Details;
        _table.FullRowSelect = true;
        _table.GridLines = true;
        _table.HeaderStyle = ColumnHeaderStyle.Nonclickable;
        _table.Columns.Add("IP", Px(115));
        _table.Columns.Add("MAC", Px(150));
        _table.Columns.Add("Type", Px(120));
        _table.Columns.Add("Network", Px(90));
        _table.Columns.Add("Notes", Px(150));
        _table.Resize += (_, _) => FitLastColumn();

        _log.Dock = DockStyle.Fill;
        _log.Multiline = true;
        _log.ReadOnly = true;
        _log.ScrollBars = ScrollBars.Vertical;
        _log.Font = new Font("Consolas", 9.5f);

        _split.Dock = DockStyle.Fill;
        _split.Orientation = Orientation.Horizontal;
        _split.Panel1.Controls.Add(_table);
        _split.Panel2.Controls.Add(_log);

        BuildTestMenu();

        Controls.Add(_split);
        Controls.Add(buttons);
        Controls.Add(_status);
        Controls.Add(_menu);
        MainMenuStrip = _menu;

        _timer.Interval = WatchIntervalMs;
        _timer.Tick += async (_, _) => await WatchTickAsync();

        _tray.Icon = SystemIcons.Shield;
        _tray.Text = "ArpGuard - watching";
        _tray.DoubleClick += (_, _) => { WindowState = FormWindowState.Normal; Activate(); };

        Shown += async (_, _) =>
        {
            _split.SplitterDistance = _split.Height / 2;
            FitLastColumn();
            await RunBusyAsync(() => RefreshAsync(writeFindings: true));
        };
        FormClosing += (_, e) =>
        {
            if (_testCts is null)
                return;
            // Let the test clean up first: an abandoned pktmon capture would keep running.
            e.Cancel = true;
            _closeAfterTest = true;
            _testCts.Cancel();
            Write("Stopping the test before closing...");
        };
        FormClosed += (_, _) =>
        {
            _timer.Stop();
            _watcher?.Dispose();
            _tray.Visible = false;
            _tray.Dispose();
        };
    }

    // ---- actions -----------------------------------------------------------

    private async Task RefreshAsync(bool writeFindings)
    {
        var store = LoadPins();
        var s = await Task.Run(() => Snapshot.Take(probeGateways: true));
        var findings = SpoofDetector.Analyze(s, store).OrderBy(f => f.Severity).ToList();
        bool danger = findings.Any(f => f.Severity == Severity.Danger);

        _alarm = false;
        ShowSnapshot(s, danger);

        if (!writeFindings)
            return;
        foreach (var f in findings)
            Write(Format(f));
        if (danger)
            Write("=> Possible ARP spoofing detected. Don't pin anything until you've investigated.");
        else if (findings.Any(f => f.Severity == Severity.Warning))
            Write("=> Nothing conclusive, but review the warnings above.");
        else
            Write("=> No signs of ARP spoofing.");
        Write("");
    }

    private async Task PinOrUnpinAsync()
    {
        if (_gatewayPinned)
            await UnpinAsync();
        else
            await PinAsync();
        await RefreshAsync(writeFindings: false);
    }

    private async Task PinAsync()
    {
        var store = LoadPins();
        var s = await Task.Run(() => Snapshot.Take(probeGateways: true));

        var candidates = s.Interfaces.Where(i => i.Gateways.Count > 0).ToList();
        if (candidates.Count == 0)
            throw new ArpGuardException("No default gateway found. Are you connected to a network?");
        if (candidates.Count > 1)
            throw new ArpGuardException(
                "Several networks have a gateway, so ArpGuard can't tell which router to pin. " +
                "Use the command-line tool instead: arpguard pin --interface <number>");

        var iface = candidates[0];
        var plan = PinService.Plan(s, iface, iface.Gateways[0], null, store);
        foreach (var p in plan.Problems)
            Write(Format(p));

        if (plan.AlreadyPinned)
        {
            PinService.Apply(plan, store);
            Write($"{plan.Ip} is already pinned to {plan.Mac}.");
            return;
        }

        // Pinning while being spoofed would lock in the attacker's MAC.
        if (plan.HasDanger)
        {
            Write("Not pinned: signs of ARP spoofing were found.");
            MessageBox.Show(this,
                "ArpGuard found signs of ARP spoofing, so it won't pin right now. You could end up " +
                "pinning the attacker's MAC instead of your router's.\n\nSee the log for details.",
                "Not pinned", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        string warnings = plan.Problems.Count == 0 ? "" :
            "\n\nWarnings:\n" + string.Join("\n", plan.Problems.Select(p => "- " + p.Message));
        var answer = MessageBox.Show(this,
            $"Pin your router so its MAC can't be spoofed?\n\n" +
            $"Network:  {iface.Name}\nRouter IP:  {plan.Ip}\nRouter MAC:  {plan.Mac}{warnings}\n\n" +
            "This survives reboots. If you replace your router, come back and click " +
            "\"Unpin gateway\" or you'll lose your connection.",
            "Pin gateway", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
        if (answer != DialogResult.Yes)
        {
            Write("Pin cancelled.");
            return;
        }

        await Task.Run(() => PinService.Apply(plan, store));
        Write($"Pinned {plan.Ip} -> {plan.Mac} on {iface.Name}.");
    }

    private async Task UnpinAsync()
    {
        var store = LoadPins();
        // No probe: if a stale pin broke the connection, pinging would just add delay.
        var s = await Task.Run(() => Snapshot.Take(probeGateways: false));
        var gatewayIps = s.Interfaces.SelectMany(i => i.Gateways).ToList();
        var targets = PinService.FindStatic(gatewayIps);
        if (targets.Count == 0)
        {
            Write("The gateway isn't pinned.");
            return;
        }

        string list = string.Join("\n", targets.Select(t => $"{t.Ip} -> {t.Mac}"));
        var answer = MessageBox.Show(this,
            $"Remove the static entry?\n\n{list}\n\nWindows will go back to learning your router's MAC " +
            "automatically, so it's no longer protected against spoofing.",
            "Unpin gateway", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
        if (answer != DialogResult.Yes)
        {
            Write("Unpin cancelled.");
            return;
        }

        var stillStatic = await Task.Run(() => PinService.Unpin(targets, store, gatewayIps));
        if (stillStatic.Count == 0)
            Write($"Unpinned {string.Join(", ", targets.Select(t => t.Ip))}.");
        foreach (var e in stillStatic)
            Write($"WARN   {e.Ip} still shows as static. Try in an admin terminal: " +
                  $"netsh interface ipv4 delete neighbors interface={e.InterfaceIndex} address={e.Ip}");
    }

    // ---- watching ----------------------------------------------------------

    private async Task ToggleWatchAsync()
    {
        if (_watcher is not null)
        {
            _timer.Stop();
            _watcher.Dispose();
            _watcher = null;
            _tray.Visible = false;
            _watch.Text = "Start watching";
            Write($"{DateTime.Now:HH:mm:ss} Stopped watching.");
            return;
        }

        _watch.Enabled = false;
        try
        {
            var watcher = new ArpWatcher(LoadPins());
            _tray.Visible = true; // needed for balloon notifications
            List<Finding> findings;
            try
            {
                findings = await Task.Run(watcher.Start);
            }
            catch
            {
                watcher.Dispose();
                throw;
            }
            _watcher = watcher;
            findings.ForEach(Report);
            ShowSnapshot(watcher.Latest!, findings.Any(f => f.Severity == Severity.Danger));
            Write($"{DateTime.Now:HH:mm:ss} Watching {watcher.DeviceCount} devices every {WatchIntervalMs / 1000}s" +
                  (watcher.CapturingPackets ? " and inspecting packets as they arrive. " : ". ") +
                  "You can minimize this window; you'll get a notification if something looks wrong.");
            _watch.Text = "Stop watching";
            _timer.Start();
        }
        catch (Exception ex)
        {
            _tray.Visible = false;
            Write("ERROR  " + ex.Message);
        }
        finally
        {
            _watch.Enabled = true;
        }
    }

    private async Task WatchTickAsync()
    {
        if (_ticking || _watcher is null)
            return;
        _ticking = true;
        var watcher = _watcher;
        try
        {
            var findings = await Task.Run(watcher.Tick);
            if (_watcher != watcher)
                return; // stopped while this tick was running
            findings.ForEach(Report);
            if (findings.Count > 0)
                ShowSnapshot(watcher.Latest!, danger: false);
        }
        catch (Exception ex)
        {
            Write("ERROR  " + ex.Message);
        }
        finally
        {
            _ticking = false;
        }
    }

    private void Report(Finding f)
    {
        Write($"{DateTime.Now:HH:mm:ss} {Format(f)}");
        if (f.Severity != Severity.Danger)
            return;
        _alarm = true;
        SystemSounds.Exclamation.Play();
        _tray.ShowBalloonTip(10_000, "ArpGuard: possible ARP spoofing", f.Message, ToolTipIcon.Warning);
    }

    // ---- tests -------------------------------------------------------------

    private void BuildTestMenu()
    {
        _testNpcap.ToolTipText =
            "Capture with Npcap (what watching uses) and show who claims to be your router and this computer.";
        _testNpcap.Click += async (_, _) => await RunTestAsync("Npcap", CaptureTest.RunNpcap);
        _testPktmon.ToolTipText =
            "Capture with Windows' built-in pktmon instead. No Npcap needed, so it double-checks the Npcap test.";
        _testPktmon.Click += async (_, _) => await RunTestAsync("pktmon", CaptureTest.RunPktmon);

        var length = new ToolStripMenuItem("Test &length");
        foreach (int seconds in new[] { 15, 30, 60, 120 })
        {
            var item = new ToolStripMenuItem($"{seconds} seconds") { Checked = seconds == _testSeconds };
            item.Click += (_, _) =>
            {
                _testSeconds = seconds;
                foreach (ToolStripMenuItem other in length.DropDownItems)
                    other.Checked = other == item;
            };
            length.DropDownItems.Add(item);
        }

        var test = new ToolStripMenuItem("&Test") { ShowShortcutKeys = false };
        test.DropDownItems.AddRange([_testNpcap, _testPktmon, new ToolStripSeparator(), length]);
        _menu.ShowItemToolTips = true;
        _menu.Items.Add(test);
    }

    private async Task RunTestAsync(
        string name, Func<Snapshot, PinStore, TimeSpan, CancellationToken, CaptureTestResult> test)
    {
        if (_testCts is not null)
            return;
        using var cts = new CancellationTokenSource();
        _testCts = cts;
        _testNpcap.Enabled = _testPktmon.Enabled = false;
        var (oldText, oldColor) = (_status.Text, _status.BackColor);
        int seconds = _testSeconds;
        SetStatus($"{name} test running ({seconds} s)...", Color.SteelBlue);
        Write($"{DateTime.Now:HH:mm:ss} {name} test: capturing for {seconds} s while pinging 1.1.1.1 once a second...");

        try
        {
            var store = LoadPins();
            var result = await Task.Run(() =>
                test(Snapshot.Take(probeGateways: true), store, TimeSpan.FromSeconds(seconds), cts.Token));

            foreach (string line in result.Report)
                Write("  " + line);
            foreach (var f in result.Findings)
                Write(Format(f));
            if (result.Danger)
            {
                Write("=> The captured traffic shows signs of ARP spoofing. See above.");
                _alarm = true;
                SetStatus("Possible ARP spoofing detected!", Color.Firebrick);
            }
            else
            {
                Write("=> No signs of ARP spoofing in the captured traffic.");
                SetStatus(oldText, oldColor);
            }
        }
        catch (OperationCanceledException)
        {
            Write("Test cancelled.");
            SetStatus(oldText, oldColor);
        }
        catch (ArpGuardException ex)
        {
            Write("ERROR  " + ex.Message);
            SetStatus(oldText, oldColor);
            if (!_closeAfterTest)
                MessageBox.Show(this, ex.Message, $"{name} test", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            Write("ERROR  " + ex);
            SetStatus(oldText, oldColor);
        }
        finally
        {
            Write("");
            _testCts = null;
            _testNpcap.Enabled = _testPktmon.Enabled = true;
            if (_closeAfterTest)
                Close();
        }
    }

    // ---- display -----------------------------------------------------------

    private void ShowSnapshot(Snapshot s, bool danger)
    {
        var duplicates = EntryText.DuplicateMacs(s);
        _table.BeginUpdate();
        _table.Items.Clear();
        foreach (var e in s.ActiveHosts().OrderBy(e => e.InterfaceIndex).ThenBy(e => IpUtil.ToUInt32(e.Ip)))
        {
            var item = new ListViewItem(
                [e.Ip.ToString(), e.Mac, EntryText.State(e), s.InterfaceName(e.InterfaceIndex), EntryText.Notes(e, s, duplicates)]);
            if (s.IsGateway(e))
                item.Font = _bold;
            if (duplicates.Contains((e.InterfaceIndex, e.Mac)))
                item.ForeColor = Color.Firebrick;
            _table.Items.Add(item);
        }
        _table.EndUpdate();

        var gatewayEntries = s.Interfaces
            .SelectMany(i => i.Gateways.Select(g => s.Find(i.Index, g)))
            .ToList();
        _gatewayPinned = gatewayEntries.Count > 0 && gatewayEntries.All(e => e is { IsStatic: true });
        _pin.Text = _gatewayPinned ? "Unpin gateway" : "Pin gateway";

        if (danger || _alarm)
            SetStatus("Possible ARP spoofing detected!", Color.Firebrick);
        else if (gatewayEntries.Count == 0)
            SetStatus("No network gateway found", Color.DimGray);
        else if (_gatewayPinned)
            SetStatus("Protected: gateway pinned", Color.SeaGreen);
        else
            SetStatus("Not protected: gateway not pinned", Color.DimGray);
    }

    private void SetStatus(string text, Color color)
    {
        _status.Text = text;
        _status.BackColor = color;
    }

    private void FitLastColumn()
    {
        int others = _table.Columns.Cast<ColumnHeader>().SkipLast(1).Sum(c => c.Width);
        _table.Columns[^1].Width = Math.Max(Px(120), _table.ClientSize.Width - others);
    }

    // ---- helpers -----------------------------------------------------------

    /// <summary>
    /// Converts a size designed at 100% display scaling to real pixels, so the layout
    /// isn't cramped on 125%/150% screens (fonts scale on their own, pixel sizes don't).
    /// </summary>
    private int Px(int logicalPixels) => LogicalToDeviceUnits(logicalPixels);

    private async Task RunBusyAsync(Func<Task> work)
    {
        _pin.Enabled = _check.Enabled = false;
        try
        {
            await work();
        }
        catch (ArpGuardException ex)
        {
            Write("ERROR  " + ex.Message);
            MessageBox.Show(this, ex.Message, "ArpGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            Write("ERROR  " + ex);
        }
        finally
        {
            _pin.Enabled = _check.Enabled = true;
        }
    }

    private PinStore LoadPins() => PinStore.Load(message => Write("WARN   " + message));

    private static string Format(Finding f) => f.Severity switch
    {
        Severity.Danger => "DANGER " + f.Message,
        Severity.Warning => "WARN   " + f.Message,
        _ => "INFO   " + f.Message,
    };

    private void Write(string text) => _log.AppendText(text + Environment.NewLine);
}
