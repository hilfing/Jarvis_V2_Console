using System.Text.RegularExpressions;
using Jarvis_V2_Console.Handlers;
using BCrypt.Net;

namespace Jarvis_V2_Console.Core;

public class UserManager
{
    private Logger logger = new Logger("JarvisAI.Core.UserManager");
    
    private static Dictionary<string, string?> UserData = new Dictionary<string, string?>
    {
        {"UserID", null},
        {"Username", null},
        {"Password", null},
        {"Email", null},
        {"FirstName", null},
        {"LastName", null},
        {"Role", null}
    };
    
    private static bool IsAuthenticated = false;
    private readonly DatabaseHandler _dbHandler;
    
    public UserManager(DatabaseHandler dbHandler)
    {
        _dbHandler = dbHandler;
        logger.Info("UserManager initialized.");
    }
    
    public bool Login(string username, string password)
    {
        logger.Info("Attempting to verify user credentials.");
        
        // Validate input
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            logger.Warning("Login attempt with invalid credentials.");
            return false;
        }

        try
        {
            bool credentialsVerified = _dbHandler.VerifyUserCredentials(username, password);
            
            if (credentialsVerified)
            {
                logger.Info("User credentials verified successfully.");
                UserData["Username"] = username;
                IsAuthenticated = true;
                return true;
            }
            
            logger.Warning("User credentials could not be verified.");
            return false;
        }
        catch (Exception ex)
        {
            logger.Error($"Login error: {ex.Message}");
            return false;
        }
    }

    public bool Register(string username, string password, string email, 
                          string firstName, string lastName)
    {
        logger.Info("Attempting to register new user.");

        // Input validation
        if (!ValidateRegistrationInput(username, password, email, firstName, lastName))
        {
            logger.Warning("Registration input validation failed.");
            return false;
        }

        try
        {
            // Hash the password before storing
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

            bool registrationResult = _dbHandler.RegisterUser(
                username, 
                hashedPassword, 
                email, 
                firstName, 
                lastName
            );

            if (registrationResult)
            {
                logger.Info("User registered successfully.");
                return true;
            }

            logger.Warning("User registration failed.");
            return false;
        }
        catch (Exception ex)
        {
            logger.Error($"Registration error: {ex.Message}");
            return false;
        }
    }

    private bool ValidateRegistrationInput(string username, string password, 
                                           string email, string firstName, string lastName)
    {
        // Username validation
        if (string.IsNullOrWhiteSpace(username) || username.Length < 3 || username.Length > 50)
        {
            logger.Warning("Invalid username length.");
            return false;
        }

        // Password complexity check
        if (string.IsNullOrWhiteSpace(password) || 
            password.Length < 8 || 
            !Regex.IsMatch(password, @"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"))
        {
            logger.Warning("Password does not meet complexity requirements.");
            return false;
        }

        // Email validation
        if (string.IsNullOrWhiteSpace(email) || 
            !Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
        {
            logger.Warning("Invalid email format.");
            return false;
        }

        // Name validations
        if (string.IsNullOrWhiteSpace(firstName) || firstName.Length > 50 ||
            string.IsNullOrWhiteSpace(lastName) || lastName.Length > 50)
        {
            logger.Warning("Invalid first or last name.");
            return false;
        }

        return true;
    }
}
