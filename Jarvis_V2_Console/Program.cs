using System.Reflection;
using Jarvis_V2_Console.Core;
using Jarvis_V2_Console.Handlers;
using Jarvis_V2_Console.Utils;
using Newtonsoft.Json.Linq;
using Spectre.Console;
using Sharprompt;

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

        GeneralUtils.VerifyDatabaseConnection(dbHandler);
        logger.Info("All configurations:" + Environment.NewLine + GeneralUtils.GetAllConfigurations().ToString());
        
        UserManager user = new UserManager(dbHandler);
        
        DisplayWelcomeMessage();
        
        bool check = user.Login("hi", "hi");
        Console.WriteLine(check);
        
        
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
    
    public static void DisplayWelcomeMessage()
    {
        // Clear the console to start fresh
        AnsiConsole.Clear();

        // Create a fancy welcome message with a border
        var panel = new Panel("[bold white]JarvisAI[/] is an AI-powered chatbot and assistant equipped with numerous features designed to make your life easier.")
            .Border(BoxBorder.Rounded)
            .Header("[bold green]Welcome to JarvisAI[/] : [bold yellow]Your AI-powered Chatbot and Assistant[/]")
            .Padding(1, 1)
            .Expand()
            .HeaderAlignment(Justify.Center);

        // Display a rich, welcoming message with beautiful formatting
        AnsiConsole.Write(panel);

        // Add a couple of styled paragraphs to guide the user
        AnsiConsole.MarkupLine("\n[bold cyan]User Settings[/]: Your personal configurations are stored in [underline]Config.ini[/] and can be easily customized.");
        AnsiConsole.MarkupLine("[bold magenta]Logs[/]: All activity logs can be found in the [underline]Logs[/] folder for reference.");
        AnsiConsole.MarkupLine("[bold red]Support[/]: If you need help, please don't hesitate to send a message to our support team.");
        AnsiConsole.MarkupLine("[bold yellow]Login/Register[/]: You must [underline]log in or register[/] to access all features of JarvisAI.");

        // A final call to action with a styled prompt
        AnsiConsole.MarkupLine("\n[bold green]Ready to begin? Let's get started with your login or registration![/]");
        AnsiConsole.MarkupLine("[italic dim]Press [bold cyan]Enter[/] to proceed.[/]");
    
        // Pause and wait for user input to proceed
        Console.ReadLine();
    }

    public static bool ChooseOption(Logger logger)
    {
        // Display the choices to the user
        var choice = Prompt.Select("Select an Option", new[] { "Login", "Register", "Exit" });

        switch (choice)
        {
            case "Login":
                // Login();
                return true;
                break;
            case "Register":
                // Register();
                return true;
                break;
            case "Exit":
                AnsiConsole.MarkupLine("[cyan]Exiting... GoodBye!![/]");
                logger.Info("User decided to Exit at Startup Prompt");
                return false;
                break;
            default:
                logger.Warning("Invalid Choice chosen by User at Startup Prompt");
                return false;
        }
    }

    
}
