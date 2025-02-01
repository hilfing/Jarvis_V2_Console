using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models.AdminAccess;

public class TokenResponse
{
    [JsonPropertyName("access_token")] public string AccessToken { get; set; }
    [JsonPropertyName("token_type")] public string TokenType { get; set; }
}