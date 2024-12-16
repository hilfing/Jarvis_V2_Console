namespace Jarvis_V2_Console.Models.Encryption;

/// <summary>
/// Possible client connection states
/// </summary>
public enum ConnectionState
{
    Disconnected,
    KeyExchangeInProgress,
    ConnectionVerificationInProgress,
    Connected
}