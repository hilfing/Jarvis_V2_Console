namespace Jarvis_V2_Console;

using System;
using System.Diagnostics;
using System.IO;
using Spectre.Console;

public class Logger
{
    public enum LogLevel
    {
        Debug,
        Info,
        Warning,
        Error,
        Critical
    }
    
    protected LogLevel ConsoleLevel { get; set; }
    protected LogLevel FileLevel { get; set; }
    private static string LogFilePath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs", $"{DateTime.Now:yyyy-MM-dd}.log");
    
    public Logger(LogLevel console = LogLevel.Warning, LogLevel file = LogLevel.Debug)
    {
        ConsoleLevel = console;
        FileLevel = file;

        string runningDir = AppDomain.CurrentDomain.BaseDirectory;
        string folderName = "Logs";
        string folderPath = Path.Combine(runningDir, folderName);


        if (!Directory.Exists(folderPath))
        {
            Directory.CreateDirectory(folderPath);
        }
    }

    private static readonly string LogTimestampFormat = "yyyy-MM-dd HH:mm:ss";

    // General log method
    private static void Log(LogLevel level, string message, string caller)
    {
        var timestamp = DateTime.Now.ToString(LogTimestampFormat);
        var logMessage = FormatLogMessage(level, timestamp, caller, message);

        if (level >= LogLevel.Debug)
        {
            WriteToFile(logMessage);
        }
        if (level >= LogLevel.Warning)
        {
            WriteToConsole(logMessage);
        }
    }

    // Formats log messages with proper markup based on log level.
    private static string FormatLogMessage(LogLevel level, string timestamp, string caller, string message)
    {
        return level switch
        {
            LogLevel.Info => $"[blue]INFO   [/]| [cyan]{timestamp}[/] | [green]{caller}[/] | {message}",
            LogLevel.Warning => $"[yellow]WARNING[/]| [cyan]{timestamp}[/] | [green]{caller}[/] | {message}",
            LogLevel.Error => $"[red]ERROR  [/]| [cyan]{timestamp}[/] | [green]{caller}[/] | {message}",
            LogLevel.Debug => $"[grey]DEBUG  [/]| [cyan]{timestamp}[/] | [green]{caller}[/] | {message}",
            LogLevel.Critical => $"[bold red]CRITICAL[/]| [cyan]{timestamp}[/] | [green]{caller}[/] | {message}",
            _ => $"[cyan]{timestamp}[/] | [green]{caller}[/] | {message}"
        };
    }

    // Writes a log message to the console.
    private static void WriteToConsole(string logMessage)
    {
        AnsiConsole.MarkupLine(logMessage);
    }

    // Writes a log message to a file.
    private static void WriteToFile(string logMessage)
    {
        try
        {
            File.AppendAllText(LogFilePath, logMessage.EscapeMarkup() + Environment.NewLine);
        }
        catch (Exception ex)
        {
            // Handle file writing exceptions gracefully.
            AnsiConsole.MarkupLine($"[red]Failed to write to log file: {ex.Message}[/]");
        }
    }


    // Retrieves the caller's type name from the stack trace.
    private static string GetCaller()
    {
        return new StackTrace().GetFrame(2)?.GetMethod()?.DeclaringType?.Name ?? "Unknown";
    }

    // Logging methods for specific log levels.
    public static void Info(string message) => Log(LogLevel.Info, message, GetCaller());
    public static void Warning(string message) => Log(LogLevel.Warning, message, GetCaller());
    public static void Error(string message) => Log(LogLevel.Error, message, GetCaller());
    public static void Debug(string message) => Log(LogLevel.Debug, message, GetCaller());
    public static void Critical(string message) => Log(LogLevel.Critical, message, GetCaller());
}
