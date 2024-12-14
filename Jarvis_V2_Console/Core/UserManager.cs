namespace Jarvis_V2_Console.Core;

public class UserManager
{
    protected static Dictionary<string, string?> UserData = new Dictionary<string, string?>
        {
            {"Username", null},
            {"Password", null},
            {"Email", null},
            {"FirstName", null},
            {"LastName", null},
            {"Role", null}
        };
}