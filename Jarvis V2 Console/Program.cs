using Jarvis_V2_Console.Handlers;

namespace Jarvis_V2_Console;

class Program
{
    static void Main(string[] args)
    {
        Logger logger = new Logger("JarvisAI.Main");
        
        var handler = new DatabaseHandler(
            host: "localhost",
            database: "exampledb",
            username: "user",
            password: "password"
        );

        Task.Run(async () =>
        {
            bool isConnected = await handler.CheckConnectionAsync();
            logger.Info($"Database connection status: {isConnected}");

            if (isConnected)
            {
                string result = await handler.ExecuteQueryAsync("SELECT NOW();");
                Console.WriteLine($"Query result: {result}");
            }
        }).GetAwaiter().GetResult();
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
        
    }
}
