using System.Security.Cryptography;

namespace Jarvis_V2_Console.Models.Encryption;

/// <summary>
/// Represents the result of a key exchange operation
/// </summary>
public class KeyExchangeResult
{
    public string ClientId { get; set; }
    public byte[] DerivedKey { get; set; }
    public ECDiffieHellmanPublicKey ServerPublicKey { get; set; }
}