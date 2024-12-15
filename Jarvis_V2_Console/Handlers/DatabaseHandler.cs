using Npgsql;
using System;
using System.Threading.Tasks;

namespace Jarvis_V2_Console.Handlers;

public class DatabaseHandler : IAsyncDisposable
{
    private readonly string _connectionString;
    private bool _disposed = false;
    Logger logger = new Logger("JarvisAI.Handlers.DatabaseHandler");

    public DatabaseHandler(string host, string database, string username, string password, int port = 5432)
    {
        // Build the connection string
        _connectionString = $"Host={host};Port={port};Username={username};Password={password};Database={database}";
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
                            logger.Info(reader[0].ToString());
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
    
    public Task CleanupAsync()
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

    public async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            await CleanupAsync();
            
            // Suppress finalization
            GC.SuppressFinalize(this);
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(DatabaseHandler));
        }
    }
    
    public bool VerifyUserCredentials(string username, string password)
    {
        logger.Debug("Verifying user credentials.");
        const string query = @"
                SELECT COUNT(1) 
                FROM users 
                WHERE username = @username AND password = @password";

        try
        {
            using (var connection = new NpgsqlConnection(_connectionString))
            {
                connection.Open();

                using (var command = new NpgsqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("username", NpgsqlTypes.NpgsqlDbType.Varchar, username);
                    command.Parameters.AddWithValue("password", NpgsqlTypes.NpgsqlDbType.Varchar, password);
                    
                    logger.Debug("Executing query to verify user credentials.");
                    
                    var result = command.ExecuteScalar();
                    logger.Info("User credentials verified.");
                    return Convert.ToInt32(result) > 0;
                }
            }
        }
        catch (Exception ex)
        {
            logger.Error("Database error during login verification. Error: " + ex.Message);
            throw;
        }
    }
}