using Jarvis_V2_Console.Core;
using Jarvis_V2_Console.Models;
using Jarvis_V2_Console.Utils;
using Microsoft.Extensions.Logging;
using Spectre.Console;

namespace Jarvis_V2_Console.Handlers;

public class SecureConnectionSetup
{
    private readonly SecureConnectionClient _client;

    private static readonly Logger logger = new Logger("JarvisAI.Handlers.SecureConnectionSetup");
    public SecureConnectionSetup (SecureConnectionClient client)
    {
        _client = client;
    }

    public async Task<OperationResult<KeyExchangeResult>> EstablishSecureConnectionAsync()
    {
        try
        {
            logger.Info("Attempting to establish secure connection");

            // Initiate key exchange
            var keyExchangeResult = await _client.InitiateKeyExchangeAsync();
            
            // Verify the connection
            bool connectionVerified = await _client.VerifyConnectionAsync(keyExchangeResult);
            
            if (connectionVerified)
            {
                logger.Info("Secure connection established successfully");
                return OperationResult<KeyExchangeResult>.Success(keyExchangeResult);
            }
            else
            {
                logger.Warning("Secure connection verification failed");
                return OperationResult<KeyExchangeResult>.Failure("Connection verification failed");
            }
        }
        catch (Exception ex)
        {
            logger.Error($"Error during secure connection setup: {ex.Message}");
            return OperationResult<KeyExchangeResult>.Failure($"Secure connection setup failed: {ex.Message}");
        }
    }

    // Method to enforce secure connection at application startup
    public static void EnforceSecureConnection(SecureConnectionClient client)
    {
        try
        {
            var setup = new SecureConnectionSetup(client);
            var connectionResult = setup.EstablishSecureConnectionAsync().GetAwaiter().GetResult();

            if (!connectionResult.IsSuccess)
            {
                AnsiConsole.MarkupLine("[red]Secure connection verification failed. Exiting...[/]");
                logger.Error($"Connection setup failed: {connectionResult.ErrorMessage}");
                Environment.Exit(1);
            }

            AnsiConsole.MarkupLine("[green]Secure connection established successfully![/]");
        }
        catch (Exception ex)
        {
            logger.Error($"Unhandled error during secure connection setup: {ex.Message}");
            Environment.Exit(1);
        }
    }
}
