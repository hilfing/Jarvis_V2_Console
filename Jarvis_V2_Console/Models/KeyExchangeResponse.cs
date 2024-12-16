using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models;

/// <summary>
/// Response from key exchange endpoint
/// </summary>
public class KeyExchangeResponse
{
    [JsonPropertyName("client_id")]
    public string client_id { get; set; }

    [JsonPropertyName("server_public_key")]
    public string server_public_key { get; set; }
}