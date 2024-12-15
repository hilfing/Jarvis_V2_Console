using Jarvis_V2_Console.Handlers;
using Sharprompt;
using Spectre.Console;

namespace Jarvis_V2_Console.Core;

public class UserManager
{
    Logger logger = new Logger("JarvisAI.Core.UserManager");
    
    protected static Dictionary<string, string?> UserData = new Dictionary<string, string?>
        {
            {"UserID", null},
            {"Username", null},
            {"Password", null},
            {"Email", null},
            {"FirstName", null},
            {"LastName", null},
            {"Role", null}
        };
    protected static bool IsAuthenticated = false;
    private readonly DatabaseHandler _dbHandler;
    
    public UserManager(DatabaseHandler dbHandler)
    {
        _dbHandler = dbHandler;
        logger.Info("UserManager initialized.");
    }
    
    public bool Login(string username, string password)
    {
        logger.Info("Attempting to verify user credentials.");
        bool c = _dbHandler.VerifyUserCredentials(username, password);
        if (c)
        {
            logger.Info("User credentials verified.");
            UserData["Username"] = username;
            UserData["Password"] = password;
            IsAuthenticated = true;
            return true;
        }
        logger.Warning("User credentials could not be verified.");
        return false;
    }
}