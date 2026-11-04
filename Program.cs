using ArpGuard;

try
{
    var cli = CliArgs.Parse(args);
    return cli.Command switch
    {
        "list" => ListCommand.Run(cli),
        "check" => await CheckCommand.RunAsync(cli),
        "pin" => PinCommand.Run(cli),
        "unpin" => UnpinCommand.Run(cli),
        "watch" => WatchCommand.Run(cli),
        "help" or "-h" or "--help" or "/?" => Help.Print(),
        _ => throw new CliException($"Unknown command '{cli.Command}'. Run 'arpguard help' for usage."),
    };
}
catch (CliException ex)
{
    Ui.Error(ex.Message);
    return 1;
}
