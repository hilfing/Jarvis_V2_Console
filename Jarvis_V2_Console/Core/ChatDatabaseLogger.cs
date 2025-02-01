using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using Jarvis_V2_Console.Handlers;
using Jarvis_V2_Console.Models;
using Jarvis_V2_Console.Utils;
using Npgsql;

namespace Jarvis_V2_Console.Core;

public class ChatDatabaseLogger : IAsyncDisposable
{
    private static readonly Logger logger = new Logger("JarvisAI.Core.ChatDatabaseLogger");
    private static DatabaseHandler _staticDbHandler;
    private static Dictionary<string, HashSet<string>> _staticSessionUsers = new Dictionary<string, HashSet<string>>();
    private static Dictionary<string, string> _userSessionMap = new Dictionary<string, string>();
    private static bool _disposed = false;

    private readonly DatabaseHandler _dbHandler;
    private readonly Dictionary<string, HashSet<string>> _sessionUsers;
    private readonly Dictionary<string, string> _userToSession;

    public ChatDatabaseLogger(DatabaseHandler dbHandler)
    {
        _dbHandler = dbHandler;
        _sessionUsers = new Dictionary<string, HashSet<string>>();
        _userToSession = new Dictionary<string, string>();
        _staticDbHandler = dbHandler;
        logger.Info("ChatDatabaseLogger initialized");
    }

    public async Task<OperationResult<string>> StartNewSession(string initiatorUsername, IEnumerable<string> participants = null)
    {
        var allParticipants = new HashSet<string> { initiatorUsername };
        if (participants != null)
        {
            foreach (var participant in participants)
            {
                allParticipants.Add(participant);
            }
        }

        var result = await _dbHandler.CreateNewChatSession(string.Join(",", allParticipants));
        if (result.IsSuccess)
        {
            string sessionId = result.Data;
            _sessionUsers[sessionId] = allParticipants;
            _staticSessionUsers[sessionId] = allParticipants;

            // Map each participant to the session
            foreach (var participant in allParticipants)
            {
                _userToSession[participant] = sessionId;
                _userSessionMap[participant] = sessionId;
            }

            logger.Info($"Started new session {sessionId} with participants: {string.Join(", ", allParticipants)}");
        }
        return result;
    }

    public async Task<OperationResult<bool>> AddUserToSession(string sessionId, string username)
    {
        if (!_sessionUsers.ContainsKey(sessionId))
        {
            logger.Warning($"Session {sessionId} not found");
            return OperationResult<bool>.Failure("Session not found");
        }

        if (_userToSession.ContainsKey(username))
        {
            logger.Warning($"User {username} is already in a session");
            return OperationResult<bool>.Failure("User is already in a session");
        }

        _sessionUsers[sessionId].Add(username);
        _staticSessionUsers[sessionId].Add(username);
        _userToSession[username] = sessionId;
        _userSessionMap[username] = sessionId;

        logger.Info($"Added user {username} to session {sessionId}");
        return OperationResult<bool>.Success(true);
    }

    public async Task<OperationResult<bool>> RemoveUserFromSession(string username)
    {
        if (!_userToSession.TryGetValue(username, out string sessionId))
        {
            logger.Warning($"User {username} not found in any session");
            return OperationResult<bool>.Failure("User not found in any session");
        }

        _sessionUsers[sessionId].Remove(username);
        _staticSessionUsers[sessionId].Remove(username);
        _userToSession.Remove(username);
        _userSessionMap.Remove(username);

        // If no users left in session, end it
        if (_sessionUsers[sessionId].Count == 0)
        {
            await EndSession(sessionId);
        }

        logger.Info($"Removed user {username} from session {sessionId}");
        return OperationResult<bool>.Success(true);
    }

    public async Task<OperationResult<bool>> LogMessage(string username, string message, bool isUserMessage)
    {
        if (!_userToSession.TryGetValue(username, out string sessionId))
        {
            logger.Warning($"No active session found for {username}");
            return OperationResult<bool>.Failure("No active session found");
        }

        return await _dbHandler.LogChatMessage(sessionId, username, message, isUserMessage);
    }

    private async Task<OperationResult<bool>> EndSession(string sessionId)
    {
        if (!_sessionUsers.ContainsKey(sessionId))
        {
            logger.Warning($"Session {sessionId} not found");
            return OperationResult<bool>.Failure("Session not found");
        }

        var result = await _dbHandler.EndChatSession(sessionId);
        if (result.IsSuccess)
        {
            var users = _sessionUsers[sessionId].ToList();
            foreach (var user in users)
            {
                _userToSession.Remove(user);
                _userSessionMap.Remove(user);
            }
            _sessionUsers.Remove(sessionId);
            _staticSessionUsers.Remove(sessionId);
            logger.Info($"Ended session {sessionId}");
        }
        return result;
    }

    public async Task<OperationResult<List<ChatMessageDto>>> GetSessionHistory(string username)
    {
        if (!_userToSession.TryGetValue(username, out string sessionId))
        {
            logger.Warning($"No active session found for {username}");
            return OperationResult<List<ChatMessageDto>>.Failure("No active session found");
        }

        return await _dbHandler.GetSessionHistory(sessionId);
    }

    public async Task<OperationResult<HashSet<string>>> GetSessionParticipants(string username)
    {
        if (!_userToSession.TryGetValue(username, out string sessionId))
        {
            logger.Warning($"No active session found for {username}");
            return OperationResult<HashSet<string>>.Failure("No active session found");
        }

        return OperationResult<HashSet<string>>.Success(_sessionUsers[sessionId]);
    }

    public static async Task<OperationResult<bool>> CleanupActiveSessions()
    {
        if (_staticDbHandler == null)
        {
            logger.Error("Static database handler not initialized");
            return OperationResult<bool>.Failure("Database handler not initialized");
        }

        logger.Info("Starting cleanup of all active sessions");
        var errors = new List<string>();

        foreach (var sessionId in _staticSessionUsers.Keys.ToList())
        {
            try
            {
                var result = await _staticDbHandler.EndChatSession(sessionId);
                if (!result.IsSuccess)
                {
                    errors.Add($"Failed to end session {sessionId}: {result.ErrorMessage}");
                    logger.Error($"Failed to end session {sessionId}: {result.ErrorMessage}");
                }
            }
            catch (Exception ex)
            {
                errors.Add($"Exception while ending session {sessionId}: {ex.Message}");
                logger.Error($"Exception while ending session {sessionId}: {ex.Message}");
            }
        }

        _staticSessionUsers.Clear();
        _userSessionMap.Clear();

        if (errors.Any())
        {
            return OperationResult<bool>.Failure($"Cleanup completed with errors: {string.Join(", ", errors)}");
        }

        logger.Info("Successfully cleaned up all active sessions");
        return OperationResult<bool>.Success(true);
    }

    public static async Task<OperationResult<bool>> CleanupOldSessions()
    {
        if (_staticDbHandler == null)
        {
            logger.Error("Static database handler not initialized");
            return OperationResult<bool>.Failure("Database handler not initialized");
        }

        var maxAge = TimeSpan.FromHours(24);
        logger.Info($"Starting cleanup of old sessions older than {maxAge.TotalHours} hours");
        
        try
        {
            var cutoffTime = DateTime.UtcNow - maxAge;
            var result = await _staticDbHandler.CleanupOldSessions(cutoffTime);
            
            if (result.IsSuccess)
            {
                var sessionsToRemove = new List<string>();
                foreach (var sessionId in _staticSessionUsers.Keys)
                {
                    if (await _staticDbHandler.IsSessionExpired(sessionId, cutoffTime))
                    {
                        sessionsToRemove.Add(sessionId);
                    }
                }

                foreach (var sessionId in sessionsToRemove)
                {
                    var users = _staticSessionUsers[sessionId];
                    foreach (var user in users)
                    {
                        _userSessionMap.Remove(user);
                    }
                    _staticSessionUsers.Remove(sessionId);
                }
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"Error during old sessions cleanup: {ex.Message}");
            return OperationResult<bool>.Failure($"Cleanup failed: {ex.Message}");
        }
    }

    private async Task CleanupAsync()
    {
        if (!_disposed)
        {
            await CleanupActiveSessions();
            _disposed = true;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await CleanupAsync();
        GC.SuppressFinalize(this);
    }
}