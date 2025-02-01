namespace Jarvis_V2_Console.Models;

public class ChatMessageDto
{
    public int Id { get; set; }
    public int ConversationId { get; set; }
    public string SessionId { get; set; }
    public string Username { get; set; }
    public string Message { get; set; }
    public bool IsUserMessage { get; set; }
    public DateTime Timestamp { get; set; }
    public DateTime UserJoinedAt { get; set; }
    public DateTime? UserLeftAt { get; set; }
}

public class ChatSessionDto
{
    public int Id { get; set; }
    public string SessionId { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime? EndTime { get; set; }
    public DateTime CreatedAt { get; set; }
    public List<ParticipantDto> Participants { get; set; } = new List<ParticipantDto>();
    public int MessageCount { get; set; }
}

public class ParticipantDto
{
    public int Id { get; set; }
    public string Username { get; set; }
    public DateTime JoinedAt { get; set; }
    public DateTime? LeftAt { get; set; }
    public bool IsActive => !LeftAt.HasValue;
}