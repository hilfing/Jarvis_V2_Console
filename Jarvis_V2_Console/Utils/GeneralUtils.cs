using System.Net.Http.Headers;
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
        ChatDatabaseLogger.CleanupActiveSessions().GetAwaiter();
        ChatDatabaseLogger.CleanupOldSessions().GetAwaiter();
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
            var response = await httpClient.GetAsync("health");
            logger.Debug($"Server Connection Status: {response.StatusCode}");
            string responseContent = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode || !responseContent.Contains("ok"))
            {
                logger.Critical($"Failed to connect to server. Status Code: {response.StatusCode}. Response: {responseContent}");
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
    public static string ConvertHtmlToMarkup(string html)
{
    if (string.IsNullOrEmpty(html))
        return html;

    // Replace common HTML tags with Spectre.Console Markup
    html = Regex.Replace(html, "<b>", "[bold]");
    html = Regex.Replace(html, "</b>", "[/]");
    html = Regex.Replace(html, "<strong>", "[bold]");
    html = Regex.Replace(html, "</strong>", "[/]");

    html = Regex.Replace(html, "<i>", "[italic]");
    html = Regex.Replace(html, "</i>", "[/]");
    html = Regex.Replace(html, "<em>", "[italic]");
    html = Regex.Replace(html, "</em>", "[/]");

    html = Regex.Replace(html, "<u>", "[underline]");
    html = Regex.Replace(html, "</u>", "[/]");

    html = Regex.Replace(html, "<s>", "[strikethrough]");
    html = Regex.Replace(html, "</s>", "[/]");
    html = Regex.Replace(html, "<strike>", "[strikethrough]");
    html = Regex.Replace(html, "</strike>", "[/]");

    html = Regex.Replace(html, "<code>", "[green3_1]");
    html = Regex.Replace(html, "</code>", "[/]");

    html = Regex.Replace(html, "<pre>", "\n[grey]");
    html = Regex.Replace(html, "</pre>", "[/]\n");

    html = Regex.Replace(html, "<blockquote>", "\n> ");
    html = Regex.Replace(html, "</blockquote>", "\n");

    html = Regex.Replace(html, "<h1>", "\n[bold][underline]");
    html = Regex.Replace(html, "</h1>", "[/][/]\n");

    html = Regex.Replace(html, "<h2>", "\n[bold]");
    html = Regex.Replace(html, "</h2>", "[/]\n");

    html = Regex.Replace(html, "<h3>", "\n[bold][italic]");
    html = Regex.Replace(html, "</h3>", "[/][/]\n");

    // Ignore color spans
    html = Regex.Replace(html, "<span style=\"color:.*?\">", "");
    html = Regex.Replace(html, "</span>", "");

    html = Regex.Replace(html, "<a href=\"(.*?)\">", "[link=$1]");
    html = Regex.Replace(html, "</a>", "[/]");

    // Handle list items with newlines
    html = Regex.Replace(html, "<li>", "\n- ");
    html = Regex.Replace(html, "</li>", "");

    // Replace <br> with a single newline
    html = Regex.Replace(html, "<br>", "\n");

    // Replace <p> with double newlines for paragraphs
    html = Regex.Replace(html, "<p>", "\n\n");
    html = Regex.Replace(html, "</p>", "\n\n");

    // Remove any remaining HTML tags
    html = Regex.Replace(html, "<.*?>", "");

    // Remove blocks starting with & and ending with ; (HTML entities)
    html = Regex.Replace(html, "&[^;]+;", "");

    // Normalize whitespace (replace multiple spaces with a single space)
    html = Regex.Replace(html, @"[ \t]+", " ");
    html = Regex.Replace(html, "&nbsp;", " ");

    // Remove leading/trailing whitespace and normalize newlines
    html = html.Trim();
    html = Regex.Replace(html, @"\n\s*\n", "\n\n"); // Preserve paragraph breaks
    html = Regex.Replace(html, @"\n+", "\n"); // Remove extra newlines
    
    return html.Trim();
}
}