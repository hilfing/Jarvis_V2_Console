using Jarvis_V2_Console.Handlers;

namespace Jarvis_V2_Console;

class Program
{
    static void Main(string[] args)
    {
        Logger logger = new Logger("JarvisAI.Main", 0, 0);
        
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
    }
}
