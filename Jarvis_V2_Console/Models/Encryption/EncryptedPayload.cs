using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models.Encryption;

/// <summary>
/// Represents an encrypted payload for network transmission
/// </summary>
public class EncryptedPayload
{
    [JsonPropertyName("iv")] public string IV { get; set; }

    [JsonPropertyName("ciphertext")] public string Ciphertext { get; set; }

    [JsonPropertyName("hmac")] public string HMAC { get; set; }

    [JsonPropertyName("hmac_key")] public string HMACKey { get; set; }
}