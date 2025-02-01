using System.Text.Json.Serialization;

namespace Jarvis_V2_Console.Models.Serializers;

[JsonSerializable(typeof(ChatData))]
[JsonSerializable(typeof(List<Dictionary<string, string>>))]
internal partial class ChatDataJsonContext : JsonSerializerContext { }