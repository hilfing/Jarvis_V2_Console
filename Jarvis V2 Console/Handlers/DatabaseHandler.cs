using Npgsql;

namespace Jarvis_V2_Console.Handlers;

public class DatabaseHandler
    {
        private readonly string _connectionString;
        Logger logger = new Logger("JarvisAI.Handlers.DatabaseHandler");

        public DatabaseHandler(string host, string database, string username, string password, int port = 5432)
        {
            // Build the connection string
            _connectionString = $"Host={host};Port={port};Username={username};Password={password};Database={database}";
        }

        /// <summary>
        /// Checks the connection to the PostgreSQL database.
        /// </summary>
        /// <returns>True if the connection is successful; otherwise, false.</returns>
        public async Task<bool> CheckConnectionAsync()
        {
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

        /// <summary>
        /// Executes a SQL query and returns the result.
        /// </summary>
        /// <param name="query">The SQL query to execute.</param>
        /// <returns>Result of the query as a string (example purpose only).</returns>
        public async Task<string> ExecuteQueryAsync(string query)
        {
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

                return "No results returned.";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error executing query: {ex.Message}");
                return null;
            }
        }
    }