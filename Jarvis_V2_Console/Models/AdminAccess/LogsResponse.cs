using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models.AdminAccess;

public class LogsResponse
{
    [JsonPropertyName("logs")]
    public LogEntry[] Logs { get; set; }
}