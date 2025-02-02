using System.Net.Http.Headers;
using System.Text.Json;
using Jarvis_V2_Console.Handlers;
using Jarvis_V2_Console.Models.AdminAccess;
using Jarvis_V2_Console.Models.Serializers.AdminAccess;
using Jarvis_V2_Console.Utils;
using Sharprompt;
using Spectre.Console;

namespace Jarvis_V2_Console.Core;

public class AdminAccessClient
{
    private static Logger logger = new Logger("JarvisAI.Core.AdminAccessClient");
    private static HttpClient _httpClient;
    private static string? _accessToken;

    public AdminAccessClient(string baseUrl)
    {
        _httpClient = new HttpClient();
        _httpClient.BaseAddress = new Uri(baseUrl);
        logger.Info($"Admin Access Client initialized.");
    }

    public async Task<OperationResult<bool>> GetAccessTokenAsync(string username, string password)
    {
        try
        {
            var request = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("password", password)
            });
            logger.Info("Requesting access token...");

            var response = await _httpClient.PostAsync("token", request);
            if (!response.IsSuccessStatusCode)
            {
                logger.Critical("Failed to get access token. Status Code: " + response.StatusCode);
                return OperationResult<bool>.Failure($"Token request failed. Status Code: {response.StatusCode}");
            }

            var content = await response.Content.ReadAsStringAsync();
            var options = new JsonSerializerOptions
            {
                TypeInfoResolver = TokenResponseJsonContext.Default
            };
            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(content, options);

            if (tokenResponse != null)
            {
                _accessToken = tokenResponse.AccessToken;
                logger.Info("Access token received successfully.");
                return OperationResult<bool>.Success(true);
            }

            logger.Critical("Failed to get access token. Unexpected response format.");
            return OperationResult<bool>.Failure($"Token request failed. Unexpected response format.");
        }
        catch (Exception e)
        {
            logger.Critical($"Failed to get access token. Exception: {e.Message}");
            return OperationResult<bool>.Failure("Token request failed. Exception: " + e.Message);
        }
    }

    public async Task<OperationResult<bool>> FetchLogsAsync(string fileName = "logs.json")
    {
        if (string.IsNullOrEmpty(_accessToken))
        {
            logger.Warning("UNAUTHORISED: Access token is missing.");
            return OperationResult<bool>.Failure("Access token is missing.");
        }

        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
        logger.Debug("Access Token Found. Fetching logs...");

        try
        {
            var response = await _httpClient.GetAsync("logs");

            if (!response.IsSuccessStatusCode)
            {
                logger.Error($"Failed to fetch logs. Status Code: {response.StatusCode}");
                return OperationResult<bool>.Failure($"Failed to fetch logs. Status Code: {response.StatusCode}");
            }

            var content = await response.Content.ReadAsStringAsync();
            var options = new JsonSerializerOptions
            {
                TypeInfoResolver = LogsJsonContext.Default
            };
            var logs = JsonSerializer.Deserialize<LogsResponse>(content, options);
            logger.Debug("Logs fetched successfully.");

            if (logs != null && logs.Logs != null)
            {
                AnsiConsole.MarkupLine("[green][bold]Success:[/] Logs fetched successfully.[/]");
                string filePath = Path.Combine(Directory.GetCurrentDirectory(), fileName);
                var jsonString = JsonSerializer.Serialize(logs, LogsJsonContext.Default.LogsResponse);
                await File.WriteAllTextAsync(filePath, GeneralUtils.FormatJsonString(jsonString));
                AnsiConsole.MarkupLine($"[green]Logs saved to [bold]{GeneralUtils.SimplifyFilePath(filePath)}[/].[/]");
                logger.Info($"Logs saved to {GeneralUtils.SimplifyFilePath(filePath)}");
                return OperationResult<bool>.Success(true);
            }
            else
            {
                logger.Error("Failed to fetch logs. Unexpected response format.");
                return OperationResult<bool>.Failure("Failed to fetch logs. Unexpected response format.");
            }
        }
        catch (Exception e)
        {
            logger.Error($"Failed to fetch logs. Exception: {e.Message}");
            return OperationResult<bool>.Failure("Failed to fetch logs. Exception: " + e.Message);
        }
    }

    public static void InvalidateClient()
    {
        _httpClient.Dispose();
        _accessToken = null;
        logger.Info("Admin Access Client disposed.");
    }
}