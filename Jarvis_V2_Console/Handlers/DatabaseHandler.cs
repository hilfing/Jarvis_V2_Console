using Jarvis_V2_Console.Models;
using Jarvis_V2_Console.Utils;
using Npgsql;

namespace Jarvis_V2_Console.Handlers;

public class DatabaseHandler : IAsyncDisposable
{
    private static bool _disposed = false;
    private static Logger logger = new Logger("JarvisAI.Core.DatabaseHandler");
    private readonly string _connectionString;

    public DatabaseHandler(string host, string database, string username, string password)
    {
        _connectionString = $"Host={host};Database={database};Username={username};Password={password}";
        logger.Info("DatabaseHandler initialized.");
    }

    public async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            await CleanupAsync();

            // Suppress finalization
            GC.SuppressFinalize(this);
        }
    }

    public OperationResult<bool> VerifyUserCredentials(string username, string password)
    {
        logger.Debug($"Verifying credentials for username: {username}");

        try
        {
            using (var connection = CreateConnection())
            {
                connection.Open();

                const string query = @"
                    SELECT password_hash 
                    FROM users 
                    WHERE username = @username";

                using (var command = new NpgsqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("username", username);

                    var storedHash = command.ExecuteScalar() as string;

                    if (storedHash == null)
                    {
                        logger.Warning($"No user found with username: {username}");
                        return OperationResult<bool>.Failure("User not found");
                    }

                    bool isValid = BCrypt.Net.BCrypt.Verify(password, storedHash);

                    if (isValid)
                    {
                        logger.Info($"Credentials verified for username: {username}");
                        return OperationResult<bool>.Success(true);
                    }

                    logger.Warning($"Invalid credentials for username: {username}");
                    return OperationResult<bool>.Failure("Invalid credentials");
                }
            }
        }
        catch (Exception ex)
        {
            logger.Error($"Credential verification error for {username}: {ex.Message}");
            return OperationResult<bool>.Failure(ex.Message);
        }
    }
    
    public OperationResult<UserDetailsDto> FetchUserDetailsByUsernameSync(string username)
    {
        logger.Debug($"Fetching details for username: {username}");

        try
        {
            using (var connection = CreateConnection())
            {
                connection.Open();

                const string query = @"
                    SELECT 
                        id, 
                        username, 
                        email, 
                        first_name, 
                        last_name, 
                        role, 
                        last_login
                    FROM users 
                    WHERE username = @username";

                using (var command = new NpgsqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("username", username);

                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            var userDetails = new UserDetailsDto
                            {
                                Id = Convert.ToInt32(reader["id"]),
                                Username = reader["username"].ToString(),
                                Email = reader["email"].ToString(),
                                FirstName = reader["first_name"].ToString(),
                                LastName = reader["last_name"].ToString(),
                                Role = reader["role"]?.ToString(),
                                LastLogin = reader["last_login"] as DateTime?
                            };

                            // Update last login
                            UpdateLastLoginTimestamp(username);

                            logger.Info($"User details fetched for {username}");
                            return OperationResult<UserDetailsDto>.Success(userDetails);
                        }

                        logger.Warning($"No user found with username: {username}");
                        return OperationResult<UserDetailsDto>.Failure("User not found");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            logger.Error($"Error fetching user details for {username}: {ex.Message}");
            return OperationResult<UserDetailsDto>.Failure(ex.Message);
        }
    }
    
    public async Task<OperationResult<UserDetailsDto>> FetchUserDetailsByUsername(string username)
    {
        logger.Debug($"Fetching details for username: {username}");

        try
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            const string query = @"
                SELECT 
                    id, 
                    username, 
                    email, 
                    first_name, 
                    last_name, 
                    role, 
                    last_login
                FROM users 
                WHERE username = @username";

            using var command = new NpgsqlCommand(query, connection);
            command.Parameters.AddWithValue("username", username);

            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                var userDetails = new UserDetailsDto
                {
                    Id = Convert.ToInt32(reader["id"]),
                    Username = reader["username"].ToString(),
                    Email = reader["email"].ToString(),
                    FirstName = reader["first_name"].ToString(),
                    LastName = reader["last_name"].ToString(),
                    Role = reader["role"]?.ToString(),
                    LastLogin = reader["last_login"] as DateTime?
                };

                await UpdateLastLoginTimestamp(username);

                logger.Info($"User details fetched for {username}");
                return OperationResult<UserDetailsDto>.Success(userDetails);
            }

            logger.Warning($"No user found with username: {username}");
            return OperationResult<UserDetailsDto>.Failure("User not found");
        }
        catch (Exception ex)
        {
            logger.Error($"Error fetching user details for {username}: {ex.Message}");
            return OperationResult<UserDetailsDto>.Failure(ex.Message);
        }
    }

    private NpgsqlConnection CreateConnection()
    {
        return new NpgsqlConnection(_connectionString);
    }

    public OperationResult<bool> RegisterUser(string username, string password,
        string email, string firstName, string lastName)
    {
        logger.Debug($"Attempting to register user: {username}");

        try
        {
            // Hash password
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

            using (var connection = CreateConnection())
            {
                connection.Open();

                const string query = @"
                    INSERT INTO users 
                    (username, password_hash, email, first_name, last_name, created_at, role) 
                    VALUES 
                    (@username, @password_hash, @email, @first_name, @last_name, @created_at, 'user')";

                using (var command = new NpgsqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("username", username);
                    command.Parameters.AddWithValue("password_hash", hashedPassword);
                    command.Parameters.AddWithValue("email", email);
                    command.Parameters.AddWithValue("first_name", firstName);
                    command.Parameters.AddWithValue("last_name", lastName);
                    command.Parameters.AddWithValue("created_at", DateTime.UtcNow);

                    int rowsAffected = command.ExecuteNonQuery();

                    if (rowsAffected > 0)
                    {
                        logger.Info($"User {username} registered successfully");
                        return OperationResult<bool>.Success(true);
                    }

                    logger.Warning($"Registration failed for {username}");
                    return OperationResult<bool>.Failure("Registration failed");
                }
            }
        }
        catch (Exception ex)
        {
            logger.Error($"Registration error for {username}: {ex.Message}");
            return OperationResult<bool>.Failure(ex.Message);
        }
    }
    public async Task<OperationResult<bool>> CleanupOldSessions(DateTime cutoffTime)
    {
        logger.Debug($"Cleaning up sessions older than: {cutoffTime}");

        try
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            const string query = @"
            UPDATE conversations 
            SET end_time = CURRENT_TIMESTAMP
            WHERE end_time IS NULL 
            AND start_time < @cutoffTime";

            using var command = new NpgsqlCommand(query, connection);
            command.Parameters.AddWithValue("cutoffTime", cutoffTime);

            int rowsAffected = await command.ExecuteNonQueryAsync();
            logger.Info($"Cleaned up {rowsAffected} old sessions");
        
            return OperationResult<bool>.Success(true);
        }
        catch (Exception ex)
        {
            logger.Error($"Error cleaning up old sessions: {ex.Message}");
            return OperationResult<bool>.Failure(ex.Message);
        }
    }

    public async Task<bool> IsSessionExpired(string sessionId, DateTime cutoffTime)
    {
        try
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            const string query = @"
            SELECT COUNT(*) 
            FROM conversations 
            WHERE session_id = @sessionId 
            AND start_time < @cutoffTime";

            using var command = new NpgsqlCommand(query, connection);
            command.Parameters.AddWithValue("sessionId", sessionId);
            command.Parameters.AddWithValue("cutoffTime", cutoffTime);

            int count = Convert.ToInt32(await command.ExecuteScalarAsync());
            return count > 0;
        }
        catch (Exception ex)
        {
            logger.Error($"Error checking session expiration: {ex.Message}");
            return false;
        }
    }
    
    public async Task<bool> CheckConnectionAsync()
    {
        ThrowIfDisposed();

        try
        {
            using (var connection = new NpgsqlConnection(_connectionString))
            {
                await connection.OpenAsync();
                logger.Debug("Successfully connected to the database.");
                return true;
            }
        }
        catch (Exception ex)
        {
            logger.Critical($"Failed to connect to the database: {ex.Message}");
            return false;
        }
    }

    public async Task<string> ExecuteQueryAsync(string query)
    {
        ThrowIfDisposed();

        try
        {
            using (var connection = new NpgsqlConnection(_connectionString))
            {
                await connection.OpenAsync();

                using (var command = new NpgsqlCommand(query, connection))
                {
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            return reader[0].ToString();
                        }
                    }
                }
            }

            logger.Warning("No results returned.");
            return "No results returned.";
        }
        catch (Exception ex)
        {
            logger.Critical($"Error executing query: {ex.Message}");
            return null;
        }
    }

    public static Task CleanupAsync()
    {
        ThrowIfDisposed();

        try
        {
            // Log the start of cleanup process
            logger.Debug("Starting database cleanup process.");

            // Clear all connection pools
            NpgsqlConnection.ClearAllPools();

            logger.Debug("Database cleanup completed successfully.");

            // Mark as disposed
            _disposed = true;

            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            logger.Critical($"Error during database cleanup: {ex.Message}");
            return Task.CompletedTask;
        }
    }

    private static void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(DatabaseHandler));
        }
    }

    public async Task<OperationResult<bool>> LogChatMessage(string sessionId, string username, string message, bool isUserMessage)
    {
        logger.Debug($"Logging chat message for session: {sessionId}");

        try
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            const string query = @"
                INSERT INTO chat_messages (
                    conversation_id,
                    session_id,
                    username,
                    message,
                    is_user_message,
                    timestamp
                )
                SELECT 
                    c.id,
                    @sessionId,
                    @username,
                    @message,
                    @isUserMessage,
                    @timestamp
                FROM conversations c
                WHERE c.session_id = @sessionId";

            using var command = new NpgsqlCommand(query, connection);
            command.Parameters.AddWithValue("sessionId", sessionId);
            command.Parameters.AddWithValue("username", username);
            command.Parameters.AddWithValue("message", message);
            command.Parameters.AddWithValue("isUserMessage", isUserMessage);
            command.Parameters.AddWithValue("timestamp", DateTime.UtcNow);

            int rowsAffected = await command.ExecuteNonQueryAsync();
            if (rowsAffected > 0)
            {
                logger.Info($"Chat message logged for session {sessionId}");
                return OperationResult<bool>.Success(true);
            }

            logger.Warning($"No active session found with ID: {sessionId}");
            return OperationResult<bool>.Failure("Session not found");
        }
        catch (Exception ex)
        {
            logger.Error($"Error logging chat message for session {sessionId}: {ex.Message}");
            return OperationResult<bool>.Failure(ex.Message);
        }
    }

    public async Task<OperationResult<bool>> EndChatSession(string sessionId)
    {
        logger.Debug($"Ending chat session: {sessionId}");

        try
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            const string query = @"
                UPDATE conversations 
                SET end_time = @endTime
                WHERE session_id = @sessionId 
                AND end_time IS NULL";

            using var command = new NpgsqlCommand(query, connection);
            command.Parameters.AddWithValue("sessionId", sessionId);
            command.Parameters.AddWithValue("endTime", DateTime.UtcNow);

            int rowsAffected = await command.ExecuteNonQueryAsync();
            if (rowsAffected > 0)
            {
                logger.Info($"Chat session ended: {sessionId}");
                return OperationResult<bool>.Success(true);
            }

            logger.Warning($"No active session found with ID: {sessionId}");
            return OperationResult<bool>.Failure("Session not found or already ended");
        }
        catch (Exception ex)
        {
            logger.Error($"Error ending chat session {sessionId}: {ex.Message}");
            return OperationResult<bool>.Failure(ex.Message);
        }
    }

    public async Task<OperationResult<List<ChatSessionDto>>> GetUserSessions(string username, DateTime? startDate = null, DateTime? endDate = null)
    {
        logger.Debug($"Fetching chat sessions for user: {username}");

        try
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            var query = @"
                SELECT 
                    id,
                    username,
                    session_id,
                    start_time,
                    end_time,
                    created_at
                FROM conversations
                WHERE username = @username";

            if (startDate.HasValue)
                query += " AND start_time >= @startDate";
            if (endDate.HasValue)
                query += " AND start_time <= @endDate";

            query += " ORDER BY start_time DESC";

            using var command = new NpgsqlCommand(query, connection);
            command.Parameters.AddWithValue("username", username);
            
            if (startDate.HasValue)
                command.Parameters.AddWithValue("startDate", startDate.Value);
            if (endDate.HasValue)
                command.Parameters.AddWithValue("endDate", endDate.Value);

            var sessions = new List<ChatSessionDto>();
            using var reader = await command.ExecuteReaderAsync();
            
            while (await reader.ReadAsync())
            {
                sessions.Add(new ChatSessionDto
                {
                    Id = Convert.ToInt32(reader["id"]),
                    SessionId = reader["session_id"].ToString(),
                    StartTime = Convert.ToDateTime(reader["start_time"]),
                    EndTime = reader["end_time"] as DateTime?,
                    CreatedAt = Convert.ToDateTime(reader["created_at"])
                });
            }

            logger.Info($"Retrieved {sessions.Count} sessions for user {username}");
            return OperationResult<List<ChatSessionDto>>.Success(sessions);
        }
        catch (Exception ex)
        {
            logger.Error($"Error fetching chat sessions for user {username}: {ex.Message}");
            return OperationResult<List<ChatSessionDto>>.Failure(ex.Message);
        }
    }
    public async Task<OperationResult<string>> CreateNewChatSession(string participants)
{
    logger.Debug($"Creating new chat session for participants: {participants}");

    try
    {
        using var connection = CreateConnection();
        await connection.OpenAsync();  // Only open the connection once
        
        using var transaction = await connection.BeginTransactionAsync();

        try
        {
            // First create the conversation
            string sessionId = $"group_{DateTime.UtcNow.Ticks}";
            
            const string conversationQuery = @"
                INSERT INTO conversations (session_id, start_time)
                VALUES (@sessionId, @startTime)
                RETURNING id";

            using var command = new NpgsqlCommand(conversationQuery, connection, transaction);
            command.Parameters.AddWithValue("sessionId", sessionId);
            command.Parameters.AddWithValue("startTime", DateTime.UtcNow);

            var conversationId = await command.ExecuteScalarAsync();

            // Then create conversation_participants entries
            const string participantQuery = @"
                INSERT INTO conversation_participants (conversation_id, username, joined_at)
                VALUES (@conversationId, @username, @joinedAt)";

            foreach (var username in participants.Split(','))
            {
                using var participantCommand = new NpgsqlCommand(participantQuery, connection, transaction);
                participantCommand.Parameters.AddWithValue("conversationId", conversationId);
                participantCommand.Parameters.AddWithValue("username", username.Trim());
                participantCommand.Parameters.AddWithValue("joinedAt", DateTime.UtcNow);
                
                await participantCommand.ExecuteNonQueryAsync();
            }

            await transaction.CommitAsync();
            
            logger.Info($"Created new chat session {sessionId} for participants: {participants}");
            return OperationResult<string>.Success(sessionId);
        }
        catch (Exception)
        {
            await transaction.RollbackAsync();
            throw;
        }
    }
    catch (PostgresException ex) when (ex.SqlState == "23503")
    {
        logger.Error($"One or more users not found in users table: {ex.Message}");
        return OperationResult<string>.Failure("One or more participants are not registered users");
    }
    catch (Exception ex)
    {
        logger.Error($"Error creating chat session: {ex.Message}");
        return OperationResult<string>.Failure(ex.Message);
    }
}

public async Task<OperationResult<bool>> AddParticipantToSession(string sessionId, string username)
{
    logger.Debug($"Adding participant {username} to session: {sessionId}");

    try
    {
        using var connection = CreateConnection();
        await connection.OpenAsync();

        const string query = @"
            INSERT INTO conversation_participants (
                conversation_id,
                username,
                joined_at
            )
            SELECT 
                c.id,
                @username,
                @joinedAt
            FROM conversations c
            WHERE c.session_id = @sessionId
            AND NOT EXISTS (
                SELECT 1 
                FROM conversation_participants cp 
                WHERE cp.conversation_id = c.id 
                AND cp.username = @username
            )";

        using var command = new NpgsqlCommand(query, connection);
        command.Parameters.AddWithValue("sessionId", sessionId);
        command.Parameters.AddWithValue("username", username);
        command.Parameters.AddWithValue("joinedAt", DateTime.UtcNow);

        int rowsAffected = await command.ExecuteNonQueryAsync();
        if (rowsAffected > 0)
        {
            logger.Info($"Added {username} to session {sessionId}");
            return OperationResult<bool>.Success(true);
        }

        logger.Warning($"Could not add {username} to session {sessionId}");
        return OperationResult<bool>.Failure("Session not found or user already in session");
    }
    catch (PostgresException ex) when (ex.SqlState == "23503")
    {
        logger.Error($"User {username} not found in users table: {ex.Message}");
        return OperationResult<bool>.Failure("User is not registered");
    }
    catch (Exception ex)
    {
        logger.Error($"Error adding participant to session: {ex.Message}");
        return OperationResult<bool>.Failure(ex.Message);
    }
}

public async Task<OperationResult<bool>> RemoveParticipantFromSession(string sessionId, string username)
{
    logger.Debug($"Removing participant {username} from session: {sessionId}");

    try
    {
        using var connection = CreateConnection();
        await connection.OpenAsync();

        const string query = @"
            UPDATE conversation_participants
            SET left_at = @leftAt
            WHERE username = @username
            AND conversation_id IN (
                SELECT id FROM conversations WHERE session_id = @sessionId
            )
            AND left_at IS NULL";

        using var command = new NpgsqlCommand(query, connection);
        command.Parameters.AddWithValue("sessionId", sessionId);
        command.Parameters.AddWithValue("username", username);
        command.Parameters.AddWithValue("leftAt", DateTime.UtcNow);

        int rowsAffected = await command.ExecuteNonQueryAsync();
        if (rowsAffected > 0)
        {
            logger.Info($"Removed {username} from session {sessionId}");
            return OperationResult<bool>.Success(true);
        }

        logger.Warning($"Could not remove {username} from session {sessionId}");
        return OperationResult<bool>.Failure("User not found in session or already removed");
    }
    catch (Exception ex)
    {
        logger.Error($"Error removing participant from session: {ex.Message}");
        return OperationResult<bool>.Failure(ex.Message);
    }
}

// Modified version of GetSessionHistory to include participant information
public async Task<OperationResult<List<ChatMessageDto>>> GetSessionHistory(string sessionId)
{
    logger.Debug($"Fetching chat history for session: {sessionId}");

    try
    {
        using var connection = CreateConnection();
        await connection.OpenAsync();

        const string query = @"
            SELECT 
                m.id,
                m.conversation_id,
                m.session_id,
                m.username,
                m.message,
                m.is_user_message,
                m.timestamp,
                cp.joined_at,
                cp.left_at
            FROM chat_messages m
            JOIN conversation_participants cp 
                ON cp.conversation_id = m.conversation_id 
                AND cp.username = m.username
            WHERE m.session_id = @sessionId
            ORDER BY m.timestamp ASC";

        using var command = new NpgsqlCommand(query, connection);
        command.Parameters.AddWithValue("sessionId", sessionId);

        var messages = new List<ChatMessageDto>();
        using var reader = await command.ExecuteReaderAsync();
        
        while (await reader.ReadAsync())
        {
            messages.Add(new ChatMessageDto
            {
                Id = Convert.ToInt32(reader["id"]),
                ConversationId = Convert.ToInt32(reader["conversation_id"]),
                SessionId = reader["session_id"].ToString(),
                Username = reader["username"].ToString(),
                Message = reader["message"].ToString(),
                IsUserMessage = Convert.ToBoolean(reader["is_user_message"]),
                Timestamp = Convert.ToDateTime(reader["timestamp"]),
                UserJoinedAt = Convert.ToDateTime(reader["joined_at"]),
                UserLeftAt = reader["left_at"] as DateTime?
            });
        }

        logger.Info($"Retrieved {messages.Count} messages for session {sessionId}");
        return OperationResult<List<ChatMessageDto>>.Success(messages);
    }
    catch (Exception ex)
    {
        logger.Error($"Error fetching chat history for session {sessionId}: {ex.Message}");
        return OperationResult<List<ChatMessageDto>>.Failure(ex.Message);
    }
}
    private async Task<bool> UpdateLastLoginTimestamp(string username)
    {
        try
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            const string query = @"
                UPDATE users 
                SET last_login = @timestamp
                WHERE username = @username";

            using var command = new NpgsqlCommand(query, connection);
            command.Parameters.AddWithValue("username", username);
            command.Parameters.AddWithValue("timestamp", DateTime.UtcNow);

            await command.ExecuteNonQueryAsync();
            return true;
        }
        catch (Exception ex)
        {
            logger.Error($"Error updating last login for {username}: {ex.Message}");
            return false;
        }
    }
}