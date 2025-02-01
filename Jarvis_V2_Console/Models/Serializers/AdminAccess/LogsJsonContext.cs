using System.Text.Json.Serialization;
using Jarvis_V2_Console.Models.AdminAccess;

namespace Jarvis_V2_Console.Models.Serializers.AdminAccess;

[JsonSerializable(typeof(LogEntry))]
[JsonSerializable(typeof(LogsResponse))]
internal partial class LogsJsonContext : JsonSerializerContext { }