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
    private string LoggerName { get; set; }
    
    public Logger(string loggerName = "JarvisAI", LogLevel consoleLevel = LogLevel.Warning, LogLevel fileLevel = LogLevel.Debug)
    {
        ConsoleLevel = consoleLevel;
        FileLevel = fileLevel;
        LoggerName = loggerName;

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
    private void Log(LogLevel level, string message, string caller)
    {
        var timestamp = DateTime.Now.ToString(LogTimestampFormat);
        var logMessage = FormatLogMessage(level, timestamp, message);

        if (level >= FileLevel)
        {
            WriteToFile(logMessage, caller);
        }
        if (level >= ConsoleLevel)
        {
            WriteToConsole(logMessage);
        }
    }

    // Formats log messages with proper markup based on log level.
    private string FormatLogMessage(LogLevel level, string timestamp, string message)
    {
        return level switch
        {
            LogLevel.Info => $"[blue]INFO   [/]| [cyan]{timestamp}[/] | [green]{LoggerName}[/] | {message}",
            LogLevel.Warning => $"[yellow]WARNING[/]| [cyan]{timestamp}[/] | [green]{LoggerName}[/] | {message}",
            LogLevel.Error => $"[red]ERROR  [/]| [cyan]{timestamp}[/] | [green]{LoggerName}[/] | {message}",
            LogLevel.Debug => $"[grey]DEBUG  [/]| [cyan]{timestamp}[/] | [green]{LoggerName}[/] | {message}",
            LogLevel.Critical => $"[bold red]CRITICAL[/]| [cyan]{timestamp}[/] | [green]{LoggerName}[/] | {message}",
            _ => $"[cyan]{timestamp}[/] | [green]{LoggerName}[/] | {message}"
        };
    }

    // Writes a log message to the console.
    private static void WriteToConsole(string logMessage)
    {
        AnsiConsole.MarkupLine(logMessage);
    }

    // Writes a log message to a file.
    private void WriteToFile(string logMessage, string caller)
    {
        try
        {
            File.AppendAllText(LogFilePath, logMessage.EscapeMarkup() + $"  [{caller}]" + Environment.NewLine);
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
    public void Info(string message) => Log(LogLevel.Info, message, GetCaller());
    public void Warning(string message) => Log(LogLevel.Warning, message, GetCaller());
    public void Error(string message) => Log(LogLevel.Error, message, GetCaller());
    public void Debug(string message) => Log(LogLevel.Debug, message, GetCaller());
    public void Critical(string message) => Log(LogLevel.Critical, message, GetCaller());
}
