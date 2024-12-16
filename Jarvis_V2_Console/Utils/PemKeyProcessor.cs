using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Jarvis_V2_Console.Utils;

public class PemKeyProcessor
{
    /// <summary>
    /// Parses a PEM-formatted public key and converts it to a byte array.
    /// </summary>
    /// <param name="pemPublicKey">The PEM-formatted public key.</param>
    /// <returns>The raw byte array of the public key.</returns>
    public static byte[] ParsePemPublicKey(string pemPublicKey)
    {
        // Remove PEM headers and footers
        string base64Key = Regex.Replace(pemPublicKey, "-----.*-----", "").Trim();

        // Decode the Base64-encoded key
        return Convert.FromBase64String(base64Key);
    }

    /// <summary>
    /// Imports a public key into an ECDiffieHellmanCng instance.
    /// </summary>
    /// <param name="publicKeyBytes">The byte array of the public key.</param>
    /// <returns>The ECDiffieHellmanCngPublicKey object.</returns>
    public static ECDiffieHellmanPublicKey ImportPublicKey(byte[] publicKeyBytes)
    {
        // Convert the byte array to an ECDiffieHellmanCngPublicKey
        return ECDiffieHellmanCngPublicKey.FromByteArray(publicKeyBytes, CngKeyBlobFormat.EccPublicBlob);
    }
}