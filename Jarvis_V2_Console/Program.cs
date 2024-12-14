using System.Reflection;
using Jarvis_V2_Console.Handlers;
using Jarvis_V2_Console.Utils;
using Newtonsoft.Json.Linq;

namespace Jarvis_V2_Console;

class Program
{
    static void Main(string[] args)
    {
        Logger logger = SetupLogger();
        
        JObject json = GetSecrets();
        JObject dbCreds = json["Database"]?.Value<JObject>() ?? new JObject();
        
        var dbHandler = new DatabaseHandler(
            host: dbCreds["Host"]?.Value<string>() ?? "localhost", 
            database: dbCreds["Database"]?.Value<string>() ?? "postgres",
            username: dbCreds["Username"]?.Value<string>() ?? "postgres",
            password: dbCreds["Password"]?.Value<string>() ?? ""
        );

        GeneralUtils.VerifyDatabaseConnection(logger, dbHandler);
        
        logger.Info("All configurations:" + Environment.NewLine + GeneralUtils.GetAllConfigurations().ToString());
        
        Cleanup(logger, dbHandler);
        
    }

    private static Logger SetupLogger()
    {
        Logger logger = new Logger("JarvisAI.Processes.Main");
        
        // Set log levels based on configuration
        Dictionary<string, Logger.LogLevel> logLevels = new Dictionary<string, Logger.LogLevel>
        {
            { "Debug", Logger.LogLevel.Debug },
            { "Info", Logger.LogLevel.Info },
            { "Warning", Logger.LogLevel.Warning },
            { "Error", Logger.LogLevel.Error },
            { "Critical", Logger.LogLevel.Critical }
        };
        string consoleLogLevel = ConfigManager.GetValue("Logging", "ConsoleLogLevel");
        string fileLogLevel = ConfigManager.GetValue("Logging", "FileLogLevel");
        if (logLevels.ContainsKey(consoleLogLevel) && logLevels.ContainsKey(fileLogLevel))
        {
            logger.ChangeLogLevel(logLevels[consoleLogLevel], logLevels[fileLogLevel]);
        }
        else
        {
            logger.Warning("Invalid log level configuration detected. Using default values.");
        }
        
        // Set log file path based on configuration
        string logFilePath = ConfigManager.GetValue("Logging", "LogFilePath");
        logger.ChangeLogFilePath(logFilePath);
        
        return logger;
    }

    private static void Cleanup(Logger logger, DatabaseHandler dbhandler)
    {
        logger.Info("Cleaning up...");
        Logger.Cleanup();
        dbhandler.CleanupAsync();
        dbhandler.DisposeAsync().GetAwaiter().GetResult();
        logger.Info("Cleanup complete.");
    }
    
    private static JObject GetSecrets()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = "Jarvis_V2_Console.secrets.json";

        JObject json;

        using (Stream stream = assembly.GetManifestResourceStream(resourceName))
        using (StreamReader reader = new StreamReader(stream))
        {
            string secrets = reader.ReadToEnd();
            json = JObject.Parse(secrets);
        }

        return json;
    }
}
