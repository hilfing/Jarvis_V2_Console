using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models.Encryption;

/// <summary>
/// Response from connection verification endpoint
/// </summary>
public class EncryptedResponse
{
    [JsonPropertyName("status")] public string status { get; set; }

    [JsonPropertyName("response_payload")]
    public EncryptedPayload response_payload { get; set; }
}