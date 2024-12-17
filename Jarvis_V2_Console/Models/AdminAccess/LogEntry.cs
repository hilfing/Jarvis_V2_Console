using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models.AdminAccess;

public class LogEntry
{
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; }

    [JsonPropertyName("logger")]
    public string Logger { get; set; }

    [JsonPropertyName("level")]
    public string Level { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; }
}