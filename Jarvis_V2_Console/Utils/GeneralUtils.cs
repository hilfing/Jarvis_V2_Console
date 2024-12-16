using System.Text.RegularExpressions;
using Jarvis_V2_Console.Core;
using Jarvis_V2_Console.Handlers;

namespace Jarvis_V2_Console.Utils;

public static class GeneralUtils
{
    private static Logger logger = new Logger("JarvisAI.Utils.GeneralUtils");

    public static string RemoveEmptyLines(string lines)
    {
        return Regex.Replace(lines, @"^\s*$\n|\r", string.Empty, RegexOptions.Multiline).TrimEnd();
    }

    public static void VerifyDatabaseConnection(DatabaseHandler dbHandler)
    {
        Task.Run(async () =>
        {
            bool isConnected = await dbHandler.CheckConnectionAsync();
            logger.Info($"Database connection status: {isConnected}");

            if (isConnected)
            {
                string result = await dbHandler.ExecuteQueryAsync("SELECT NOW();");
                logger.Debug($"DataBase Server Time: {result}");
            }
        }).GetAwaiter().GetResult();
    }

    public static void Cleanup()
    {
        logger.Info("Cleaning up...");
        Logger.Cleanup();
        DatabaseHandler.CleanupAsync();
        SecureConnectionClient.InvalidateConnection();
        logger.Info("Cleanup complete.");
    }


    // Helper method to simplify file path
    public static string SimplifyFilePath(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath))
            return null;

        // Split the path and take the last two components
        string[] pathParts = fullPath.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);

        return pathParts.Length > 1
            ? string.Join("/", pathParts.Skip(Math.Max(0, pathParts.Length - 2)))
            : fullPath;
    }
}