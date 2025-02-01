using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models;

public class ChatData
{
    [JsonPropertyName("msg")]
    public string Msg { get; set; }

    [JsonPropertyName("history")]
    public List<Dictionary<string, string>> History { get; set; }
}