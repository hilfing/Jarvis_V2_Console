using System.Text.Json.Serialization;
using Jarvis_V2_Console.Models.AdminAccess;

namespace Jarvis_V2_Console.Models.Serializers.AdminAccess;


[JsonSerializable(typeof(TokenResponse))]
internal partial class TokenResponseJsonContext : JsonSerializerContext { }