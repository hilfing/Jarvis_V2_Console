using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace Jarvis_V2_Console.Handlers;

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
    private static string LogFilePath { get; set; } = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs", $"{DateTime.Now:yyyy-MM-dd-HH-mm-ss}.log");
    private string LoggerName { get; set; }
    
    protected static StringBuilder InternalLogCache = new StringBuilder();
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

    private static readonly string LogTimestampFormat = "yyyy-MM-dd HH:mm:ss:fff";
    
    public static void Cleanup()
    {
        InternalLogCache.Clear();
    }
    public void ChangeLogLevel(LogLevel consoleLevel, LogLevel fileLevel)
    {
        Log(LogLevel.Debug, "Changing log levels...", GetCaller());
        ConsoleLevel = consoleLevel;
        FileLevel = fileLevel;
        Log(LogLevel.Debug, $"Console log level set to: {consoleLevel}", GetCaller());
        Log(LogLevel.Debug, $"File log level set to: {fileLevel}", GetCaller());
    }
    
    public void ChangeLogFilePath(string path)
    {
        try
        {
            LogFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, path, $"{DateTime.Now:yyyy-MM-dd-HH-mm-ss}.log");
            string runningDir = AppDomain.CurrentDomain.BaseDirectory;
            string folderPath = Path.Combine(runningDir, path);
            if (!Directory.Exists(folderPath))
            {
                Directory.CreateDirectory(folderPath);
            }
            Log(LogLevel.Debug, $"Log file path changed to: {LogFilePath}", GetCaller());
            
            File.AppendAllText(LogFilePath, InternalLogCache.ToString());
            Log(LogLevel.Debug, "Internal log cache written to new log file.", GetCaller());
            
        }
        catch (Exception)
        {
            Log(LogLevel.Warning, "Invalid file path provided. Log file path remains unchanged.", GetCaller());
            AnsiConsole.MarkupLine("[red]Invalid file path provided. Log file path remains unchanged.[/]");
        }
    }

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

        if (level >= LogLevel.Critical)
        {
            Environment.Exit(1);
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
    
    static string RemoveMarkup(string input)
    {
        // Regex to match Spectre.Console markup tags
        var regex = new Regex(@"\[(?:(?:bold\s*)?[a-z]+)\]|\[/\]", RegexOptions.IgnoreCase);
        return regex.Replace(input, string.Empty);
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
            if (logMessage.Contains("Error") || logMessage.Contains("CRITICAL") || logMessage.Contains("WARNING"))
            {
                File.AppendAllText(LogFilePath,
                    RemoveMarkup(logMessage) + Environment.NewLine + caller + Environment.NewLine);
                InternalLogCache.AppendLine(RemoveMarkup(logMessage) + Environment.NewLine + caller);
            }
            else
            {
                File.AppendAllText(LogFilePath, RemoveMarkup(logMessage) + Environment.NewLine);
                InternalLogCache.AppendLine(RemoveMarkup(logMessage));
            }
            
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Failed to write to log file: {ex.Message}[/]");
        }
    }


    private static string GetCaller()
    {
    try
    {
        // Get the stack trace
        StackTrace stackTrace = new StackTrace(true);
        
        // Directly get frame 2
        StackFrame frame = stackTrace.GetFrame(2);
        
        if (frame == null)
        {
            return "Frame 2 is null";
        }
        
        MethodBase method = frame.GetMethod();
        
        if (method == null)
        {
            return "Method in frame 2 is null";
        }
        
        // Collect detailed information
        StringBuilder callerInfo = new StringBuilder();
        
        // Declaring Type Information
        string declaringTypeName = method.DeclaringType?.FullName ?? "Unknown";
        
        // Extract method name from declaring type for compiler-generated async methods
        string methodName = declaringTypeName.Contains("<") 
            ? ExtractMethodNameFromDeclaringType(declaringTypeName) 
            : method.Name;
        
        // Declaring Type Information
        callerInfo.AppendLine($"Declaring Type: {declaringTypeName}");
        
        // Method Name
        callerInfo.AppendLine($"Method Name: {methodName}");
        
        // Namespace
        callerInfo.AppendLine($"Namespace: {method.DeclaringType?.Namespace ?? "Unknown"}");
        
        // Method Signature
        callerInfo.AppendLine($"Method Signature: {method}");
        
        // Source File and Line Number
        string fileName = SimplifyFilePath(frame.GetFileName());
        int lineNumber = frame.GetFileLineNumber();
        
        callerInfo.AppendLine($"Source File: {fileName ?? "Unknown"}");
        callerInfo.AppendLine($"Line Number: {(lineNumber > 0 ? lineNumber.ToString() : "Unknown")}");
        
        return callerInfo.ToString();
    }
    catch (Exception ex)
    {
        return $"Error retrieving caller information: {ex.Message}";
    }
}

// Helper method to extract method name from compiler-generated type names
    private static string ExtractMethodNameFromDeclaringType(string declaringTypeName)
    {
        // First, try the original pattern with << and >
        int startIndex = declaringTypeName.IndexOf("<<");
        int endIndex = startIndex >= 0 
            ? declaringTypeName.IndexOf(">", startIndex + 2)
            : -1;

        if (startIndex >= 0 && endIndex > startIndex)
        {
            return declaringTypeName.Substring(startIndex + 2, endIndex - startIndex - 2);
        }

        // If the first pattern fails, try the alternative pattern with <> and >
        startIndex = declaringTypeName.IndexOf("<");
        endIndex = startIndex >= 0 
            ? declaringTypeName.IndexOf(">", startIndex)
            : -1;

        if (startIndex >= 0 && endIndex > startIndex)
        {
            return declaringTypeName.Substring(startIndex + 1, endIndex - startIndex - 1);
        }

        // If no pattern matches, return "Unknown"
        return "Unknown";
    }

// Helper method to simplify file path
private static string SimplifyFilePath(string fullPath)
{
    if (string.IsNullOrEmpty(fullPath))
        return null;
    
    // Split the path and take the last two components
    string[] pathParts = fullPath.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
    
    return pathParts.Length > 1 
        ? string.Join("/", pathParts.Skip(Math.Max(0, pathParts.Length - 2)))
        : fullPath;
}

    // Logging methods for specific log levels.
    public void Info(string message) => Log(LogLevel.Info, message, GetCaller());
    public void Warning(string message) => Log(LogLevel.Warning, message, GetCaller());
    public void Error(string message) => Log(LogLevel.Error, message, GetCaller());
    public void Debug(string message) => Log(LogLevel.Debug, message, GetCaller());
    public void Critical(string message) => Log(LogLevel.Critical, message, GetCaller());
}
