using System.Reflection;
using System.Text.RegularExpressions;
using Jarvis_V2_Console.Core;
using Jarvis_V2_Console.Handlers;
using Jarvis_V2_Console.Utils;
using Newtonsoft.Json.Linq;
using Spectre.Console;
using Sharprompt;

namespace Jarvis_V2_Console;

public static class Program
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
        UserManager userManager = new UserManager(dbHandler);
        
        DisplayWelcomeMessage();

        switch (ChooseOption(logger))
        {
            case 1:
                List<string> loginData = Login(logger);
                bool loginSuccess = userManager.Login(loginData[0], loginData[1]);
                if (!loginSuccess)
                {
                    AnsiConsole.MarkupLine("[red]Login failed. Please try again.[/]");
                }
                else
                {
                    AnsiConsole.MarkupLine("[green]Login successful![/]");
                }
                break;
            case 2:
                List<string> registrationData = Register(logger, dbHandler);
                OperationResult<bool> registrationSuccess = userManager.Register(
                    registrationData[0],  // username
                    registrationData[1],  // password
                    registrationData[2],  // email
                    registrationData[3],  // firstName
                    registrationData[4]   // lastName
                );
                if (registrationSuccess.IsSuccess)
                {
                    AnsiConsole.MarkupLine("[green]Registration successful![/]");
                }
                else
                {
                    AnsiConsole.MarkupLine("[red]Registration failed. Please try again.[/]");
                }
                break;
            case null:
                Cleanup(logger, dbHandler);
                return;
        }

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

    public static int? ChooseOption(Logger logger)
    {
        // Display the choices to the user
        var choice = Prompt.Select("Select an Option", new[] { "Login", "Register", "Exit" });

        switch (choice)
        {
            case "Login":
                return 1;
                break;
            case "Register":
                return 2;
                break;
            case "Exit":
                AnsiConsole.MarkupLine("[cyan]Exiting... GoodBye!![/]");
                logger.Info("User decided to Exit at Startup Prompt");
                return null;
                break;
            default:
                logger.Warning("Invalid Choice chosen by User at Startup Prompt");
                ChooseOption(logger);
                return null;
        }
    }
    
    private static List<string> Login(Logger logger)
    {
        AnsiConsole.MarkupLine("[bold cyan]Login[/]: Please enter your credentials to log in.");
        logger.Debug("User selected Login option.");
        string username = Prompt.Input<string>("Username:");
        logger.Debug($"User entered username: {username}");
        string password = Prompt.Password("Password:");
        logger.Debug("User entered password.");
        return new List<string> { username, password };
    }
    
    private static List<string> Register(Logger logger, DatabaseHandler dbhandler)
    {
        AnsiConsole.MarkupLine("[bold cyan]Register[/]: Please provide your details.");
        logger.Debug("User selected Registration option.");
        string username = "", password = "", email = "", firstName = "", lastName = "";
        try
        {
            username = GetValidatedInput(
                prompt: "Username:",
                validationFunc: ValidateUsername,
                errorMessage: "[red]Invalid username. Must be 3-50 characters long.[/]"
            );

            password = GetValidatedInput(
                prompt: "Password:",
                validationFunc: ValidatePassword,
                errorMessage:
                "[red]Invalid password. Must be at least 8 characters with a letter, number, and special character.[/]",
                isPassword: true
            );

            email = GetValidatedInput(
                prompt: "Email:",
                validationFunc: ValidateEmail,
                errorMessage: "[red]Invalid email format. Please enter a valid email address.[/]"
            );

            firstName = GetValidatedInput(
                prompt: "First Name:",
                validationFunc: ValidateName,
                errorMessage: "[red]Invalid first name. Must be 1-50 characters long.[/]"
            );

            lastName = GetValidatedInput(
                prompt: "Last Name:",
                validationFunc: ValidateName,
                errorMessage: "[red]Invalid last name. Must be 1-50 characters long.[/]"
            );
        }
        catch (OperationCanceledException ex)
        {
            AnsiConsole.MarkupLine("[yellow]Registration cancelled by user.[/]");
            logger.Warning("User cancelled registration.");
            Cleanup(logger, dbhandler);
            Environment.Exit(0);
        }

        logger.Debug("User completed registration input.");
        
        return new List<string> { username, password, email, firstName, lastName };
    }

private static string GetValidatedInput(
    string prompt, 
    Func<string, bool> validationFunc, 
    string errorMessage, 
    bool isPassword = false)
{
    while (true)
    {
        string input;
        if (isPassword)
        {
            input = Prompt.Password(prompt);
        }
        else
        {
            input = Prompt.Input<string>(prompt);
        }

        if (validationFunc(input))
        {
            return input;
        }

        AnsiConsole.MarkupLine(errorMessage);
        
        // Option to cancel registration
        if (!AnsiConsole.Confirm("[yellow]Would you like to try again?[/]"))
        {
            throw new OperationCanceledException("Registration cancelled by user.");
        }
    }
}

private static bool ValidateUsername(string username)
{
    // Username validation: 3-50 characters, no special characters except underscore
    return !string.IsNullOrWhiteSpace(username) && 
           username.Length >= 3 && 
           username.Length <= 50 &&
           Regex.IsMatch(username, @"^[a-zA-Z0-9_]+$");
}

private static bool ValidatePassword(string password)
{
    // Password complexity: 
    // - At least 8 characters
    // - At least one uppercase letter
    // - At least one lowercase letter
    // - At least one number
    // - At least one special character
    return !string.IsNullOrWhiteSpace(password) && 
           password.Length >= 8 && 
           Regex.IsMatch(password, @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$");
}

private static bool ValidateEmail(string email)
{
    // Comprehensive email validation
    return !string.IsNullOrWhiteSpace(email) && 
           Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$") &&
           email.Length <= 100;
}

private static bool ValidateName(string name)
{
    // Name validation: 1-50 characters, allows letters, spaces, and hyphens
    return !string.IsNullOrWhiteSpace(name) && 
           name.Length >= 1 && 
           name.Length <= 50 &&
           Regex.IsMatch(name, @"^[a-zA-Z\-\s]+$");
}
    
}
