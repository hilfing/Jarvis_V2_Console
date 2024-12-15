using Npgsql;
using BCrypt.Net;
using Jarvis_V2_Console.Utils;
using Jarvis_V2_Console.Models;

namespace Jarvis_V2_Console.Handlers;

public class DatabaseHandler : IAsyncDisposable
{
    private Logger logger = new Logger("JarvisAI.Core.DatabaseHandler");
    private readonly string _connectionString;
    private bool _disposed = false;

    public DatabaseHandler(string host, string database, string username, string password)
    {
        _connectionString = $"Host={host};Database={database};Username={username};Password={password}";
        logger.Info("DatabaseHandler initialized.");
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

    public OperationResult<UserDetailsDto> FetchUserDetailsByUsername(string username)
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

    private void UpdateLastLoginTimestamp(string username)
    {
        logger.Debug($"Updating last login timestamp for {username}");

        try
        {
            using (var connection = CreateConnection())
            {
                connection.Open();

                const string updateQuery = @"
                    UPDATE users 
                    SET last_login = @last_login 
                    WHERE username = @username";

                using (var command = new NpgsqlCommand(updateQuery, connection))
                {
                    command.Parameters.AddWithValue("username", username);
                    command.Parameters.AddWithValue("last_login", DateTime.UtcNow);

                    command.ExecuteNonQuery();
                }
            }
        }
        catch (Exception ex)
        {
            logger.Error($"Error updating last login timestamp for {username}: {ex.Message}");
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
                    (username, password_hash, email, first_name, last_name, created_at, updated_at) 
                    VALUES 
                    (@username, @password_hash, @email, @first_name, @last_name, @created_at, @updated_at)";

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
}