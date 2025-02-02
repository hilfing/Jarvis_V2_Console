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
    
    private static readonly Dictionary<string, (string opening, string closing)> TagMap = new()
    {
        { "b", ("[bold]", "[/]") },
        { "strong", ("[bold]", "[/]") },
        { "i", ("[italic]", "[/]") },
        { "em", ("[italic]", "[/]") },
        { "u", ("[underline]", "[/]") },
        { "s", ("[strikethrough]", "[/]") },
        { "strike", ("[strikethrough]", "[/]") },
        { "code", ("[green3_1]", "[/]") },
        { "pre", ("[grey]", "[/]") },
        { "h1", ("[bold][underline]", "[/][/]") },
        { "h2", ("[bold][italic]", "[/][/]") },
        { "h3", ("[bold]", "[/]") }
    };

    public static string ConvertHtmlToMarkup(string html)
    {
        if (string.IsNullOrEmpty(html))
            return html;

        var lines = new List<string>();
        var currentLine = new List<string>();
        var stack = new Stack<string>();

        // Split into individual elements
        var elements = Regex.Split(html, "(<[^>]+>)")
                          .Where(s => !string.IsNullOrWhiteSpace(s))
                          .Select(s => s.Trim());

        foreach (var element in elements)
        {
            if (element.StartsWith("<"))
            {
                if (element.StartsWith("</")) // Closing tag
                {
                    var tagName = Regex.Match(element, @"</(\w+)").Groups[1].Value.ToLower();
                    
                    // Handle specific closing tags
                    switch (tagName)
                    {
                        
                        case "h3":
                        case "h2":
                        case "li":
                            if (stack.Count > 0) currentLine.Add(stack.Pop());
                            lines.Add(string.Join("", currentLine));
                            currentLine.Clear();
                            break;
                        
                        case "ul":
                            lines.Add(string.Join("", currentLine));
                            currentLine.Clear();
                            break;
                            
                        case "p":
                        case "h1":
                        case "br":
                            if (stack.Count > 0) currentLine.Add(stack.Pop());
                            lines.Add(string.Join("", currentLine));
                            lines.Add(""); // Add a newline
                            currentLine.Clear();
                            break;
                        
                        default:
                            if (stack.Count > 0) currentLine.Add(stack.Pop());
                            break;
                    }
                }
                else // Opening tag
                {
                    var match = Regex.Match(element, @"<(\w+)(?:\s+href=""([^""]+)"")?");
                    var tagName = match.Groups[1].Value.ToLower();
                    
                    switch (tagName)
                    {
                        case "a":
                            var href = match.Groups[2].Value;
                            currentLine.Add($"[link={href}]");
                            stack.Push("[/]");
                            break;
                            
                        case "li":
                            currentLine.Add("- ");
                            break;
                            
                        case "ul":
                        case "ol":
                            if (currentLine.Any())
                            {
                                lines.Add(string.Join("", currentLine));
                                currentLine.Clear();
                            }
                            break;
                            
                        default:
                            if (TagMap.ContainsKey(tagName))
                            {
                                var (opening, closing) = TagMap[tagName];
                                currentLine.Add(opening);
                                stack.Push(closing);
                            }
                            break;
                    }
                }
            }
            else // Text content
            {
                currentLine.Add(element);
            }
        }

        // Add any remaining content
        if (currentLine.Any())
        {
            lines.Add(string.Join("", currentLine));
        }

        // Clean up the output
        var result = string.Join("\n", lines)
            .Replace("\n\n\n", "\n\n")  // Remove triple newlines
            .Replace("  ", " ")         // Remove double spaces
            .Trim();
        logger.Debug($"Converted HTML to markup:\n{result}");
        return result;
    }
}