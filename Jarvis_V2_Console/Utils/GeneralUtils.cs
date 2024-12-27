using System.Reflection;
using System.Text.RegularExpressions;
using Jarvis_V2_Console.Core;
using Jarvis_V2_Console.Handlers;
using Newtonsoft.Json.Linq;

namespace Jarvis_V2_Console.Utils;

public static class GeneralUtils
{
    private static Logger logger = new Logger("JarvisAI.Utils.GeneralUtils");

    public static string RemoveEmptyLines(string lines)
    {
        return Regex.Replace(lines, @"^\s*$\n|\r", string.Empty, RegexOptions.Multiline).TrimEnd();
    }

    public static void VerifyDatabaseConnection(DatabaseHandler dbHandler)
    {
        Task.Run(async () =>
        {
            bool isConnected = await dbHandler.CheckConnectionAsync();
            logger.Info($"Database connection status: {isConnected}");

            if (isConnected)
            {
                string result = await dbHandler.ExecuteQueryAsync("SELECT NOW();");
                logger.Debug($"DataBase Server Time: {result}");
            }
        }).GetAwaiter().GetResult();
    }

    public static void Cleanup()
    {
        logger.Info("Cleaning up...");
        Logger.Cleanup();
        DatabaseHandler.CleanupAsync();
        SecureConnectionClient.InvalidateConnection();
        AdminAccessClient.InvalidateClient();
        logger.Info("Cleanup complete.");
    }


    // Helper method to simplify file path
    public static string SimplifyFilePath(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath))
            return null;

        // Split the path and take the last two components
        string[] pathParts = fullPath.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);

        return pathParts.Length > 1
            ? string.Join("/", pathParts.Skip(Math.Max(0, pathParts.Length - 2)))
            : fullPath;
    }
    
    public static void VerifyServerConnection(string BaseUrl)
    {
        Task.Run(async () =>
        {
            HttpClient httpClient = new HttpClient();
            httpClient.BaseAddress = new Uri(BaseUrl);
            logger.Info($"Verifying server connection to API...");
            var response = await httpClient.GetAsync("/health");
            string responseContent = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode || !responseContent.Contains("ok"))
            {
                logger.Critical($"Failed to connect to server. Status Code: {response.StatusCode}");
            }
            else
            {
                logger.Info("Server connection verified successfully.");
            }
        }).GetAwaiter().GetResult();
    }
    
    public static JObject GetSecrets()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = "Jarvis_V2_Console.secrets.json";

        JObject json;

        try
        {
            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            using (StreamReader reader = new StreamReader(stream))
            {
                string secrets = reader.ReadToEnd();
                json = JObject.Parse(secrets);
            }

            return json;
        }
        catch (Newtonsoft.Json.JsonReaderException)
        {
            logger.Error("Jarvis AI Server Credentials not found. \nIf you are a Developer, please check your 'secrets.json' file.");
            return new JObject();
        }
    }
}