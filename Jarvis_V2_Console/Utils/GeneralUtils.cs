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
                Console.WriteLine($"DataBase Server Time: {result}");
            }
        }).GetAwaiter().GetResult();
    }
    
    public static string GetAllConfigurations()
    {
        StringBuilder sb = new StringBuilder();
        logger.Debug("Logging contents of config.ini:");
        var allConfigs = ConfigManager.GetAllConfigurations();
        foreach (var section in allConfigs)
        {
            sb.AppendLine($"Section: {section.Key}");
            foreach (var setting in section.Value)
            {
                sb.AppendLine($"  {setting.Key}: {setting.Value}");
            }
        }
        
        string resultString = RemoveEmptyLines(sb.ToString());
        return resultString;
    }
    
}