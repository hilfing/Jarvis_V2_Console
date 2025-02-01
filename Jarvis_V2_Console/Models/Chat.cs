namespace Jarvis_V2_Console.Models;

public class ChatSession
{
    public int ConversationId { get; set; }
    public string Username { get; set; }
    public string SessionId { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime? EndTime { get; set; }
}

public class ChatMessage
{
    public int Id { get; set; }
    public int ConversationId { get; set; }
    public string SessionId { get; set; }
    public string Username { get; set; }
    public string Message { get; set; }
    public bool IsUserMessage { get; set; }
    public DateTime Timestamp { get; set; }
}