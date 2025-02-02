using System.Text.Json;
using System.Text.Json.Serialization;
using Jarvis_V2_Console.Models.AdminAccess;

namespace Jarvis_V2_Console.Models.Serializers.AdminAccess;

[JsonSerializable(typeof(LogsResponse))]
[JsonSerializable(typeof(LogEntry))]
internal partial class LogsJsonContext : JsonSerializerContext {}