using System.Text.RegularExpressions;
using Jarvis_V2_Console.Handlers;
using Sharprompt;
using Spectre.Console;

namespace Jarvis_V2_Console.Utils;

public static class InputValidator
{
    private static Logger logger = new Logger("JarvisAI.Utils.InputValidator");

    public static string GetValidatedInput(
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
                if (validationFunc == ValidatePassword || validationFunc == ValidateEmail)
                {
                    logger.Info(
                        $"Input Validation Success: [ Type: {validationFunc.Method.Name} | Input: {new string('*', input.Length)} ]");
                    return input;
                }
                else
                {
                    logger.Info($"Input Validation Success: [ Type: {validationFunc.Method.Name} | Input: {input} ]");
                    return input;
                }
            }

            logger.Info(
                $"Input Validation Error: \nType: {validationFunc.Method.Name} | Input: {input} | Error: {errorMessage}");
            AnsiConsole.MarkupLine(errorMessage);

            // Option to cancel registration
            if (!AnsiConsole.Confirm("[yellow]Would you like to try again?[/]"))
            {
                throw new OperationCanceledException("Registration cancelled by user.");
            }
        }
    }

    public static bool ValidateUsername(string username)
    {
        // Username validation: 3-50 characters, no special characters except underscore
        return !string.IsNullOrWhiteSpace(username) &&
               username.Length >= 3 &&
               username.Length <= 50 &&
               Regex.IsMatch(username, @"^[a-zA-Z0-9_]+$");
    }

    public static bool ValidatePassword(string password)
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

    public static bool ValidateEmail(string email)
    {
        // Comprehensive email validation
        return !string.IsNullOrWhiteSpace(email) &&
               Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$") &&
               email.Length <= 100;
    }

    public static bool ValidateName(string name)
    {
        // Name validation: 1-50 characters, allows letters, spaces, and hyphens
        return !string.IsNullOrWhiteSpace(name) &&
               name.Length >= 1 &&
               name.Length <= 50 &&
               Regex.IsMatch(name, @"^[a-zA-Z\-\s]+$");
    }
}