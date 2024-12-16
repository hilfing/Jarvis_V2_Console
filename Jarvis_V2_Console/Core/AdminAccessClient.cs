using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Jarvis_V2_Console.Handlers;
using Jarvis_V2_Console.Models.AdminAccess;
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
        logger.Info($"Admin Access Client initialized. Base URL: {baseUrl}");
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

            var response = await _httpClient.PostAsJsonAsync("/token", request);
            if (!response.IsSuccessStatusCode)
            {
                logger.Error("Failed to get access token. Status Code: " + response.StatusCode);
                return OperationResult<bool>.Failure($"Token request failed. Status Code: {response.StatusCode}");
            }

            var content = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(content);

            if (tokenResponse != null)
            {
                _accessToken = tokenResponse.AccessToken;
                logger.Info("Access token received successfully.");
                return OperationResult<bool>.Success(true);
            }

            logger.Error("Failed to get access token. Unexpected response format.");
            return OperationResult<bool>.Failure($"Token request failed. Unexpected response format.");
        }
        catch (Exception e)
        {
            logger.Error($"Failed to get access token. Exception: {e.Message}");
            return OperationResult<bool>.Failure("Token request failed. Exception: " + e.Message);
        }
    }

    public async Task<OperationResult<bool>> FetchLogsAsync()
    {
        if (string.IsNullOrEmpty(_accessToken))
        {
            logger.Warning("UNAUTHORISED: Access token is missing.");
            return OperationResult<bool>.Failure("Access token is missing.");
        }

        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);

        try
        {
            var response = await _httpClient.GetAsync("/logs");

            if (!response.IsSuccessStatusCode)
            {
                logger.Error($"Failed to fetch logs. Status Code: {response.StatusCode}");
                return OperationResult<bool>.Failure($"Failed to fetch logs. Status Code: {response.StatusCode}");
            }

            var content = await response.Content.ReadAsStringAsync();
            var logs = JsonSerializer.Deserialize<LogsResponse>(content);

            if (logs != null && logs.Logs != null)
            {
                AnsiConsole.MarkupLine("[green][bold]Success:[/] Logs fetched successfully.[/]");
                var filePath = Prompt.Input<string>("Enter file name", "logs.json");
                await File.WriteAllTextAsync(filePath,
                    JsonSerializer.Serialize(logs, new JsonSerializerOptions { WriteIndented = true }));
                AnsiConsole.MarkupLine($"[green]Logs saved to [bold]{GeneralUtils.SimplifyFilePath(filePath)}[/].[/]");
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