using System.Security.Cryptography;
using System.Text;
using Jarvis_V2_Console.Models;


namespace Jarvis_V2_Console.Handlers;

/// <summary>
    /// Handles encryption and decryption operations
    /// </summary>
    public class CryptoHandler
    {
        
        private static Logger logger = new Logger("JarvisAI.Handlers.CryptoHandler");
        
        /// <summary>
        /// Performs AES encryption with HMAC for message security
        /// </summary>
        public static EncryptedPayload EncryptMessage(byte[] key, byte[] message)
{
    try
    {
        // Detailed logging of input parameters
        logger.Debug($"EncryptMessage called with:");
        logger.Debug($"Key Length: {key?.Length ?? 0} bytes");
        logger.Debug($"Message Length: {message?.Length ?? 0} bytes");
        logger.Debug($"Key (Base64): {Convert.ToBase64String(key)}");
        logger.Debug($"Message (Base64): {Convert.ToBase64String(message)}");

        // Generate random IV
        byte[] iv = new byte[16];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(iv);
        }
        logger.Debug($"Generated IV (Base64): {Convert.ToBase64String(iv)}");
        logger.Debug($"IV Length: {iv.Length} bytes");

        // Use AES CBC mode with PKCS7 padding
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;

        logger.Debug($"AES Mode: {aes.Mode}");
        logger.Debug($"Padding Mode: {aes.Padding}");
        logger.Debug($"Key for AES (Base64): {Convert.ToBase64String(aes.Key)}");

        // Encrypt
        using var encryptor = aes.CreateEncryptor();
        byte[] ciphertext = encryptor.TransformFinalBlock(message, 0, message.Length);
        
        logger.Debug($"Ciphertext Length: {ciphertext.Length} bytes");
        logger.Debug($"Ciphertext (Base64): {Convert.ToBase64String(ciphertext)}");

        // Use the first 32 bytes of the key as HMAC key
        byte[] hmacKey = new byte[32];
        Array.Copy(key, hmacKey, Math.Min(key.Length, 32));
        
        logger.Debug($"HMAC Key Length: {hmacKey.Length} bytes");
        logger.Debug($"HMAC Key (Base64): {Convert.ToBase64String(hmacKey)}");

        // Compute HMAC using SHA384
        using var hmac = new HMACSHA384(hmacKey);
        byte[] hmacDigest = hmac.ComputeHash(ciphertext);
        
        logger.Debug($"HMAC Digest Length: {hmacDigest.Length} bytes");
        logger.Debug($"HMAC Digest (Base64): {Convert.ToBase64String(hmacDigest)}");

        // Prepare payload with detailed logging of encoded values
        var payload = new EncryptedPayload
        {
            IV = Convert.ToBase64String(iv),
            Ciphertext = Convert.ToBase64String(ciphertext),
            HMAC = Convert.ToBase64String(hmacDigest),
            HMACKey = Convert.ToBase64String(hmacKey)
        };

        logger.Debug("Encryption Payload Details:");
        logger.Debug($"IV (Base64 Encoded): {payload.IV}");
        logger.Debug($"Ciphertext (Base64 Encoded): {payload.Ciphertext}");
        logger.Debug($"HMAC (Base64 Encoded): {payload.HMAC}");
        logger.Debug($"HMAC Key (Base64 Encoded): {payload.HMACKey}");

        return payload;
    }
    catch (Exception ex)
    {
        logger.Error($"Encryption failed with detailed error: {ex}");
        logger.Error($"Exception Type: {ex.GetType().FullName}");
        logger.Error($"Stack Trace: {ex.StackTrace}");
        throw;
    }
}

public static byte[] DecryptMessage(byte[] key, EncryptedPayload payload)
{
    try
    {

        // Decode payload components
        byte[] iv = Convert.FromBase64String(payload.IV);
        byte[] ciphertext = Convert.FromBase64String(payload.Ciphertext);
        byte[] hmacDigest = Convert.FromBase64String(payload.HMAC);
        byte[] hmacKey = Convert.FromBase64String(payload.HMACKey);

        // HMAC Verification
        using var hmac = new HMACSHA384(hmacKey);
        byte[] computedHmac = hmac.ComputeHash(ciphertext);

        if (!ConstantTimeCompare(hmacDigest, computedHmac))
        {
            logger.Warning("HMAC verification failed");
            throw new CryptographicException("HMAC verification failed");
        }

        // Decrypt using AES CBC with PKCS7 padding
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        byte[] decrypted = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);

        return decrypted;
    }
    catch (Exception ex)
    {
        logger.Error("Decryption failed. Error: " + ex);
        logger.Error($"Exception Type: {ex.GetType().FullName}");
        logger.Error($"Stack Trace: {ex.StackTrace}");
        throw;
    }
}


// Constant time comparison method
private static bool ConstantTimeCompare(byte[] a, byte[] b)
{
    if (a == null || b == null || a.Length != b.Length)
        return false;

    uint result = 0;
    for (int i = 0; i < a.Length; i++)
    {
        result |= (uint)(a[i] ^ b[i]);
    }
    return result == 0;
}

        private static byte[] GenerateRandomKey(int length)
        {
            using var rng = new RNGCryptoServiceProvider();
            byte[] key = new byte[length];
            rng.GetBytes(key);
            return key;
        }
        
        public static byte[] DeriveSharedSecret(ECDiffieHellman clientPrivateKey, byte[] serverPublicKeyBytes)
        {
            try 
            {
                // For .NET 8+, use DeriveRawSecretAgreement
                using var serverPublicKey = ECDiffieHellman.Create();
                serverPublicKey.ImportSubjectPublicKeyInfo(serverPublicKeyBytes, out _);

                // Derive raw shared secret
                byte[] sharedSecret = clientPrivateKey.DeriveRawSecretAgreement(serverPublicKey.PublicKey);

                // Implement HKDF more closely matching Python's cryptography library
                // Step 1: Extract - use HMAC with empty salt
                using var hmac = new HMACSHA384();
                hmac.Key = new byte[hmac.HashSize / 8]; // Zero-length key
                byte[] pseudoRandomKey = hmac.ComputeHash(sharedSecret);

                // Step 2: Expand - use HMAC with PRK and info
                using var expandHmac = new HMACSHA384(pseudoRandomKey);
                byte[] info = Encoding.UTF8.GetBytes("handshake data");
        
                // Perform expansion to generate output keying material
                byte[] outputKeyingMaterial = new byte[32];
                byte[] currentBlock = new byte[0];
        
                for (int i = 1; currentBlock.Length < outputKeyingMaterial.Length; i++)
                {
                    // Concatenate previous block, info, and counter
                    byte[] input = currentBlock
                        .Concat(info)
                        .Concat(new[] { (byte)i })
                        .ToArray();
            
                    // Generate next block
                    currentBlock = expandHmac.ComputeHash(input);
            
                    // Copy to output, not exceeding desired length
                    int copyLength = Math.Min(currentBlock.Length, outputKeyingMaterial.Length - (i - 1) * currentBlock.Length);
                    Array.Copy(currentBlock, 0, outputKeyingMaterial, (i - 1) * currentBlock.Length, copyLength);
                }
                

                return outputKeyingMaterial;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Key Derivation Error: {ex.Message}");
                throw;
            }
        }
    }