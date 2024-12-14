using System.Reflection;
using System.Runtime.CompilerServices;
using Jarvis_V2_Console.Handlers;
using Newtonsoft.Json.Linq;

namespace Jarvis_V2_Console;

class Program
{
    static void Main(string[] args)
    {
        Logger logger = SetupLogger();
        
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = "Jarvis_V2_Console.secrets.json";

        JObject json;

        using (Stream stream = assembly.GetManifestResourceStream(resourceName))
        using (StreamReader reader = new StreamReader(stream))
        {
            string secrets = reader.ReadToEnd();
            json = JObject.Parse(secrets);
        }
        
        JObject dbCreds = json["Database"]?.Value<JObject>() ?? new JObject();
        
        var handler = new DatabaseHandler(
            host: dbCreds["Host"]?.Value<string>() ?? "localhost", 
            database: dbCreds["Database"]?.Value<string>() ?? "postgres",
            username: dbCreds["Username"]?.Value<string>() ?? "postgres",
            password: dbCreds["Password"]?.Value<string>() ?? ""
        );

        Task.Run(async () =>
        {
            bool isConnected = await handler.CheckConnectionAsync();
            logger.Info($"Database connection status: {isConnected}");

            if (isConnected)
            {
                string result = await handler.ExecuteQueryAsync("SELECT NOW();");
                Console.WriteLine($"DataBase Server Time: {result}");
            }
        }).GetAwaiter().GetResult();
        
        // ConfigManager Testing Code
        /*
         try
        {
            // Get a specific configuration value
            string connectionString = ConfigManager.GetValue("Database", "ConnectionString");
            Console.WriteLine($"Current DB Connection: {connectionString}");

            // Update a configuration value
            ConfigManager.UpdateValue("Database", "ConnectionString", "Server=newhost;Database=newdb;");

            // Get all configurations
            var allConfigs = ConfigManager.GetAllConfigurations();
            foreach (var section in allConfigs)
            {
                Console.WriteLine($"Section: {section.Key}");
                foreach (var setting in section.Value)
                {
                    Console.WriteLine($"  {setting.Key}: {setting.Value}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Configuration Error: {ex.Message}");
        }
        */
        
    }

    private static Logger SetupLogger()
    {
        Logger logger = new Logger("JarvisAI.Main");
        
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

    private static void Cleanup(Logger logger)
    {
        logger.Info("Cleaning up...");
        Logger.Cleanup();
    }
}
