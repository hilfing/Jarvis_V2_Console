using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models.Encryption;

public class KeyExchangeRequest
{
    [JsonPropertyName("client_public_key")]
    public string ClientPublicKey { get; set; }

    [JsonPropertyName("client_id")]
    public string ClientId { get; set; }
}