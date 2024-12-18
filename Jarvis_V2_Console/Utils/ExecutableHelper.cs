namespace Jarvis_V2_Console.Utils;

using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

public class ExecutableHelper
{

    public static string GetExecutableDirectory()
    {
        string exePath = GetExecutablePath();

        if (exePath != null)
        {
            string exeDir = Path.GetDirectoryName(exePath);

            // Check if it's a single-file executable running from a temp directory
            if (exeDir.Contains("Temp", StringComparison.OrdinalIgnoreCase))
            {
                // Adjust if running from temp folder due to single-file extraction
                exeDir = GetOriginalExecutableDirectory();
            }

            return exeDir;
        }

        return string.Empty;
    }

    public static string GetExecutablePath()
    {
        string exePath = Assembly.GetEntryAssembly()?.Location;

        // If Assembly.GetEntryAssembly() returns null, fallback to the current process executable path
        if (string.IsNullOrEmpty(exePath))
        {
            exePath = Process.GetCurrentProcess().MainModule.FileName;
        }

        return exePath;
    }

    public static bool IsRunningFromTempDirectory()
    {
        string exePath = GetExecutablePath();
        return exePath != null && exePath.Contains("Temp", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetOriginalExecutableDirectory()
    {
        string appDir = string.Empty;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // On Windows, use Environment.GetCommandLineArgs to get the original .exe path
            appDir = Path.GetDirectoryName(Environment.GetCommandLineArgs()[0]);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            // On Linux/macOS, use Process.GetCurrentProcess().MainModule.FileName
            appDir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
        }

        return appDir;
    }

    public static string GetConfigDirectory()
    {
        // Common location for all platforms (e.g., AppData or ProgramData)
        string baseDir = string.Empty;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "YourAppName");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal), ".config", "YourAppName");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal), "Library", "Application Support", "YourAppName");
        }

        // Ensure the directory exists
        Directory.CreateDirectory(baseDir);
        return baseDir;
    }
    
    public static string GetExecutableFilePath(string fileName)
    {
        string exeDir = GetExecutableDirectory();
        return Path.Combine(exeDir, fileName);
    }
}
