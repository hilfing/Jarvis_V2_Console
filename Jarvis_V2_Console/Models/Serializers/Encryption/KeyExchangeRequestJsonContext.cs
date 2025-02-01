using System.Text.Json.Serialization;
using Jarvis_V2_Console.Models.Encryption;

namespace Jarvis_V2_Console.Models.Serializers.Encryption;

[JsonSerializable(typeof(KeyExchangeRequest))]
internal partial class KeyExchangeRequestJsonContext : JsonSerializerContext { }