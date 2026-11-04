namespace ArpGuard;

internal static class Ui
{
    public static void Line(ConsoleColor color, string text)
    {
        var old = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ForegroundColor = old;
    }

    public static void Ok(string text) => Line(ConsoleColor.Green, "[ OK ]   " + text);
    public static void Info(string text) => Line(ConsoleColor.Cyan, "[INFO]   " + text);
    public static void Warn(string text) => Line(ConsoleColor.Yellow, "[WARN]   " + text);
    public static void Danger(string text) => Line(ConsoleColor.Red, "[DANGER] " + text);
    public static void Error(string text) => Line(ConsoleColor.Red, "error: " + text);

    public static void Show(Finding f)
    {
        switch (f.Severity)
        {
            case Severity.Danger: Danger(f.Message); break;
            case Severity.Warning: Warn(f.Message); break;
            default: Info(f.Message); break;
        }
    }

    public static bool Confirm(string question)
    {
        Console.Write(question + " [y/N] ");
        string? answer = Console.ReadLine()?.Trim().ToLowerInvariant();
        return answer is "y" or "yes";
    }

    public static void Table(string[] headers, IReadOnlyList<string[]> rows, string indent = "  ")
    {
        var widths = headers.Select(h => h.Length).ToArray();
        foreach (var row in rows)
            for (int i = 0; i < row.Length; i++)
                widths[i] = Math.Max(widths[i], row[i].Length);

        string Format(string[] cells) =>
            indent + string.Join("  ", cells.Select((c, i) => c.PadRight(widths[i]))).TrimEnd();

        Line(ConsoleColor.DarkGray, Format(headers));
        foreach (var row in rows)
            Console.WriteLine(Format(row));
    }
}
