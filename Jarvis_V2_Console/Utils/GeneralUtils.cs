using System.Text;
using System.Text.RegularExpressions;
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
    
}