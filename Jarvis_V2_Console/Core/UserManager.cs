using System.Text.RegularExpressions;
using Jarvis_V2_Console.Handlers;
using Jarvis_V2_Console.Utils;

namespace Jarvis_V2_Console.Core;

public class UserManager
{
    private static Dictionary<string, string?> UserData = new Dictionary<string, string?>
    {
        { "UserID", null },
        { "Username", null },
        { "Email", null },
        { "FirstName", null },
        { "LastName", null },
        { "Role", null },
        { "LastLogin", null }
    };

    private static bool IsAuthenticated = false;
    private readonly DatabaseHandler _dbHandler;
    private Logger logger = new Logger("JarvisAI.Core.UserManager");

    public UserManager(DatabaseHandler dbHandler)
    {
        _dbHandler = dbHandler;
        logger.Info("UserManager initialized.");
    }

    public bool Login(string username, string password, bool reg = false)
    {
        logger.Info($"Login attempt initiated for username: {username}");

        if (reg)
        {
            logger.Debug("Registration flag detected. Skipping login verification.");
            logger.Info($"Login Confirmed for User: {username}");
            return true;
        }

        if (IsAuthenticated)
        {
            logger.Warning("User already authenticated.");
            return false;
        }

        // Input validation
        if (string.IsNullOrWhiteSpace(username))
        {
            logger.Warning("Login attempt with empty username.");
            return false;
        }

        try
        {
            // Verify credentials
            var loginResult = _dbHandler.VerifyUserCredentials(username, password);

            if (loginResult.IsSuccess)
            {
                logger.Info($"Credentials verified for username: {username}");

                // Fetch and store user details
                var detailsResult = FetchUserDetails(username);

                if (detailsResult.IsSuccess)
                {
                    IsAuthenticated = true;
                    logger.Info($"User {username} logged in successfully.");
                    return true;
                }

                logger.Warning($"Login successful but user details fetch failed for {username}.");
                return false;
            }

            logger.Warning($"Invalid credentials for username: {username}");
            return false;
        }
        catch (Exception ex)
        {
            logger.Error($"Login error for username {username}: {ex.Message}");
            return false;
        }
    }

    public OperationResult<bool> FetchUserDetails(string username)
    {
        logger.Debug($"Attempting to fetch details for username: {username}");

        try
        {
            // Use DatabaseHandler method to fetch user details
            var detailsResult = _dbHandler.FetchUserDetailsByUsername(username);

            if (detailsResult.IsSuccess && detailsResult.Data != null)
            {
                var userDetails = detailsResult.Data;

                // Update static UserData
                UserData["UserID"] = userDetails.Id.ToString();
                UserData["Username"] = userDetails.Username;
                UserData["Email"] = userDetails.Email;
                UserData["FirstName"] = userDetails.FirstName;
                UserData["LastName"] = userDetails.LastName;
                UserData["LastLogin"] = userDetails.LastLogin?.ToString();

                logger.Info($"User details successfully fetched for {username}");
                return OperationResult<bool>.Success(true);
            }

            logger.Warning($"Failed to fetch user details for {username}");
            return OperationResult<bool>.Failure("User details not found");
        }
        catch (Exception ex)
        {
            logger.Error($"Error fetching user details for {username}: {ex.Message}");
            return OperationResult<bool>.Failure(ex.Message);
        }
    }

    public OperationResult<bool> Register(string username, string password,
        string email, string firstName, string lastName)
    {
        logger.Info($"Registration attempt for username: {username}");

        try
        {
            // Validate input
            var validationResult = ValidateRegistrationInput(username, password, email, firstName, lastName);
            if (!validationResult)
            {
                logger.Warning($"Registration validation failed");
                return OperationResult<bool>.Failure("Invalid input");
            }

            // Use DatabaseHandler to register user
            var registrationResult = _dbHandler.RegisterUser(
                username,
                password,
                email,
                firstName,
                lastName
            );

            if (registrationResult.IsSuccess)
            {
                logger.Info($"User {username} registered successfully");
                Login(username, password, true);
                return OperationResult<bool>.Success(true);
            }

            logger.Warning($"Registration failed for {username}.");
            return registrationResult;
        }
        catch (Exception ex)
        {
            logger.Error($"Registration error for {username}: {ex.Message}");
            return OperationResult<bool>.Failure(ex.Message);
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