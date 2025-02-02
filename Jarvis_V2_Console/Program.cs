﻿using System.Reflection;
using System.Runtime.InteropServices.JavaScript;
using Jarvis_V2_Console.Core;
using Jarvis_V2_Console.Handlers;
using Jarvis_V2_Console.Screens;
using Jarvis_V2_Console.Utils;

using Newtonsoft.Json.Linq;
using Sharprompt;
using Spectre.Console;

namespace Jarvis_V2_Console;

public static class Program
{
    static void Main(string[] args)
    {
        Logger logger = null;
        JObject json = null;
        DatabaseHandler dbHandler = null;
        SecureConnectionClient client = null;
        AdminAccessClient adminAccessClient = null;
        ChatDatabaseLogger chatLogger = null;

        AnsiConsole.Clear();
        AnsiConsole.Write(new FigletText("JarvisAI V2").Color(Color.Green).Centered());
        try
        {
            AnsiConsole.Progress()
                .AutoClear(false)
                .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(),
                    new SpinnerColumn())
                .Start(ctx =>
                {
                    // Create a single progress task
                    var setupTask = ctx.AddTask("[yellow]Initializing Application[/]");

                    // Dynamic status updates
                    if (!ctx.IsFinished)
                    {
                        AnsiConsole.MarkupLine("[blue]Starting setup...[/]");
                        Thread.Sleep(200); // Simulate initial delay
                    }

                    // Setting up Logger
                    AnsiConsole.MarkupLine("[green]Step 1:[/] Setting up Logger and reading Configuration files...");
                    Thread.Sleep(100);
                    logger = SetupLogger();
                    logger.Debug($"Running Directory: {ExecutableHelper.GetExecutableDirectory()}");
                    setupTask.Increment(10);

                    // Retrieving Secrets
                    AnsiConsole.MarkupLine("[green]Step 2:[/] Retrieving Server Credentials...");
                    Thread.Sleep(100);
                    json = GeneralUtils.GetSecrets();
                    setupTask.Increment(10);

                    // Setting up Database Connection
                    AnsiConsole.MarkupLine("[green]Step 3:[/] Establishing Database Connection...");
                    Thread.Sleep(200);
                    JObject dbCreds = json["Database"]?.Value<JObject>() ?? new JObject();
                    dbHandler = new DatabaseHandler(
                        host: dbCreds["Host"]?.Value<string>() ?? "localhost",
                        database: dbCreds["Database"]?.Value<string>() ?? "postgres",
                        username: dbCreds["Username"]?.Value<string>() ?? "postgres",
                        password: dbCreds["Password"]?.Value<string>() ?? ""
                    );
                    GeneralUtils.VerifyDatabaseConnection(dbHandler);
                    setupTask.Increment(20);

                    // Setting up Secure API Connection
                    AnsiConsole.MarkupLine("[green]Step 4:[/] Establishing Secure API Connection...");
                    JObject apiCreds = json["API"]?.Value<JObject>() ?? new JObject();
                    string baseUrl = apiCreds["BaseUrl"]?.Value<string>() ?? "http://localhost:8000/jarvis/v1/";
                    adminAccessClient =
                        new AdminAccessClient(baseUrl);
                    GeneralUtils.VerifyServerConnection(baseUrl);
                    setupTask.Increment(20);
                    string? adminUsername = apiCreds["AdminUsername"]?.Value<string>() ?? "admin";
                    string? adminPassword = apiCreds["AdminPassword"]?.Value<string>() ?? "admin";
                    adminAccessClient.GetAccessTokenAsync(adminUsername, adminPassword).GetAwaiter().GetResult();
                    setupTask.Increment(20);
                    
                    AnsiConsole.MarkupLine("[green]Step 5:[/] Setting up End to End Encryption Channel...");
                    client = new SecureConnectionClient(baseUrl);
                    SecureConnectionSetup.EnforceSecureConnection(client);
                    setupTask.Increment(20);
                });
        }
        catch (Exception e)
        {
            logger.Critical("Failure to load JarvisAI. Please contact the Developer.");
            GeneralUtils.Cleanup();
            Environment.Exit(1);
            return;
        }

        AnsiConsole.Status().Start("Loading JarvisAI...", ctx =>
        {
            ctx.Spinner(Spinner.Known.Star);
            Thread.Sleep(2000);
        });

        DisplayWelcomeMessage();
        
        UserManager userManager = new UserManager(dbHandler);

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
                    registrationData[0], // username
                    registrationData[1], // password
                    registrationData[2], // email
                    registrationData[3], // firstName
                    registrationData[4] // lastName
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
                GeneralUtils.Cleanup();
                return;
        }
        if (userManager.IsUserAuthenticated())
        {
            AnsiConsole.MarkupLine("[green]User authenticated successfully![/]");
            chatLogger = new ChatDatabaseLogger(dbHandler);
            string username = userManager.GetUserData("Username");
            chatLogger.StartNewSession(username, new []{username, "Jarvis"}).GetAwaiter().GetResult();
            var chatScreen = new ChatScreen();
            chatScreen.StartChat(client,adminAccessClient ,chatLogger, username);
        }
        else
        {
            logger.Error("User not logged in. Exiting...");
            GeneralUtils.Cleanup();
            return;
        }
        GeneralUtils.Cleanup();
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

    public static void DisplayWelcomeMessage()
    {
        // Clear the console to start fresh
        AnsiConsole.Clear();

        // Initial welcome text
        string welcomeText =
            "JarvisAI is an AI-powered chatbot and assistant equipped with numerous features designed to make your life easier.";

        // Create a Live display for the welcome panel
        AnsiConsole.Live(new Panel(""))
            .Start(ctx =>
            {
                // Typing effect for welcome text
                for (int i = 1; i <= welcomeText.Length; i++)
                {
                    // Create a new panel with progressively longer text
                    var panel = new Panel(welcomeText.Substring(0, i))
                        .Border(BoxBorder.Rounded)
                        .Header(
                            "[bold green]Welcome to JarvisAI[/] : [bold yellow]Your AI-powered Chatbot and Assistant[/]")
                        .Padding(1, 1)
                        .Expand()
                        .HeaderAlignment(Justify.Center);

                    // Update the live context with new panel
                    ctx.UpdateTarget(panel);

                    // Control typing speed
                    Thread.Sleep(20);
                }
            });

        AnsiConsole.MarkupLine(
            "\n[bold cyan]User Settings[/]: Your personal configurations are stored in [underline]Config.ini[/] and can be easily customized.");
        Thread.Sleep(500);
        AnsiConsole.MarkupLine(
            "[bold magenta]Logs[/]: All activity logs can be found in the [underline]Logs[/] folder for reference.");
        Thread.Sleep(500);
        AnsiConsole.MarkupLine(
            "[bold red]Support[/]: If you need help, please don't hesitate to send a message to our support team.");
        Thread.Sleep(500);
        AnsiConsole.MarkupLine(
            "[bold yellow]Login/Register[/]: You must [underline]log in or register[/] to access all features of JarvisAI.");
        Thread.Sleep(1000);

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
            username = InputValidator.GetValidatedInput(
                prompt: "Username:",
                validationFunc: InputValidator.ValidateUsername,
                errorMessage: "[red]Invalid username. Must be 3-50 characters long.[/]"
            );

            password = InputValidator.GetValidatedInput(
                prompt: "Password:",
                validationFunc: InputValidator.ValidatePassword,
                errorMessage:
                "[red]Invalid password. Must be at least 8 characters with a letter, number, and special character.[/]",
                isPassword: true
            );

            email = InputValidator.GetValidatedInput(
                prompt: "Email:",
                validationFunc: InputValidator.ValidateEmail,
                errorMessage: "[red]Invalid email format. Please enter a valid email address.[/]"
            );

            firstName = InputValidator.GetValidatedInput(
                prompt: "First Name:",
                validationFunc: InputValidator.ValidateName,
                errorMessage: "[red]Invalid first name. Must be 1-50 characters long.[/]"
            );

            lastName = InputValidator.GetValidatedInput(
                prompt: "Last Name:",
                validationFunc: InputValidator.ValidateName,
                errorMessage: "[red]Invalid last name. Must be 1-50 characters long.[/]"
            );
        }
        catch (OperationCanceledException ex)
        {
            AnsiConsole.MarkupLine("[yellow]Registration cancelled by user.[/]");
            logger.Warning("User cancelled registration.");
            GeneralUtils.Cleanup();
            Environment.Exit(0);
        }

        logger.Debug("User completed registration input.");

        return new List<string> { username, password, email, firstName, lastName };
    }
}