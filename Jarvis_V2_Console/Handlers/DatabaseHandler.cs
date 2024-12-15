using Npgsql;
using BCrypt.Net;

namespace Jarvis_V2_Console.Handlers;

public class DatabaseHandler : IAsyncDisposable
{
    private readonly string _connectionString;
    private bool _disposed = false;
    private Logger logger = new Logger("JarvisAI.Core.DatabaseHandler");

    public DatabaseHandler(string host, string database, string username, string password)
    {
        _connectionString = $"Host={host};Database={database};Username={username};Password={password}";
        logger.Info("DatabaseHandler initialized.");
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
            SELECT password_hash 
            FROM users 
            WHERE username = @username";

        try
        {
            using (var connection = new NpgsqlConnection(_connectionString))
            {
                connection.Open();

                using (var command = new NpgsqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("username", username);
                    
                    var storedHash = command.ExecuteScalar() as string;
                    
                    return storedHash != null && 
                           BCrypt.Net.BCrypt.Verify(password, storedHash);
                }
            }
        }
        catch (Exception ex)
        {
            logger.Error($"Database error during login verification: {ex.Message}");
            throw;
        }
    }

    public bool RegisterUser(string username, string hashedPassword, 
                              string email, string firstName, string lastName)
    {
        logger.Debug("Attempting to register new user in database.");
        
        const string query = @"
            INSERT INTO users 
            (username, password_hash, email, first_name, last_name, created_at, updated_at) 
            VALUES 
            (@username, @password_hash, @email, @first_name, @last_name, @created_at, @updated_at)";

        try
        {
            using (var connection = new NpgsqlConnection(_connectionString))
            {
                connection.Open();

                using (var command = new NpgsqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("username", username);
                    command.Parameters.AddWithValue("password_hash", hashedPassword);
                    command.Parameters.AddWithValue("email", email);
                    command.Parameters.AddWithValue("first_name", firstName);
                    command.Parameters.AddWithValue("last_name", lastName);
                    command.Parameters.AddWithValue("created_at", DateTime.UtcNow);
                    command.Parameters.AddWithValue("updated_at", DateTime.UtcNow);

                    int rowsAffected = command.ExecuteNonQuery();
                    
                    return rowsAffected > 0;
                }
            }
        }
        catch (Exception ex)
        {
            logger.Error($"Database error during user registration: {ex.Message}");
            throw;
        }
    }
}