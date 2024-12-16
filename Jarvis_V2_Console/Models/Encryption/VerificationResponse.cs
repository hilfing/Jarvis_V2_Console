using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models.Encryption;

/// <summary>
/// Response from connection verification endpoint
/// </summary>
public class VerificationResponse
{
    [JsonPropertyName("status")] public string status { get; set; }

    [JsonPropertyName("verification_payload")]
    public EncryptedPayload verification_payload { get; set; }
}