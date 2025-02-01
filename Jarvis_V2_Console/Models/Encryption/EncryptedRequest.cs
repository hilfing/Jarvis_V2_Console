using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models.Encryption;

public class EncryptedRequest
{
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; }
    [JsonPropertyName("encrypted_payload")]
    public EncryptedPayload EncryptedPayload { get; set; }
}