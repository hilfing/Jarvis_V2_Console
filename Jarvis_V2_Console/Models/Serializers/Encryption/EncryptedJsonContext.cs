using System.Text.Json.Serialization;
using Jarvis_V2_Console.Models.Encryption;

namespace Jarvis_V2_Console.Models.Serializers.Encryption;

[JsonSerializable(typeof(EncryptedPayload))]
[JsonSerializable(typeof(EncryptedResponse))]
[JsonSerializable(typeof(EncryptedRequest))]
internal partial class EncryptedJsonContext : JsonSerializerContext { }