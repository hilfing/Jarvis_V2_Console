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
                using var aes = Aes.Create();
                aes.Key = key;
                aes.GenerateIV();

                // Padding
                int paddedLength = ((message.Length + 15) / 16) * 16;
                byte[] paddedMessage = new byte[paddedLength];
                Buffer.BlockCopy(message, 0, paddedMessage, 0, message.Length);

                using var encryptor = aes.CreateEncryptor();
                byte[] ciphertext = encryptor.TransformFinalBlock(paddedMessage, 0, paddedMessage.Length);

                // HMAC Generation
                using var hmac = new HMACSHA384();
                hmac.Key = GenerateRandomKey(32);
                byte[] hmacDigest = hmac.ComputeHash(ciphertext);

                logger.Debug($"Message encrypted successfully. Ciphertext length: {ciphertext.Length}");

                return new EncryptedPayload
                {
                    IV = Convert.ToBase64String(aes.IV),
                    Ciphertext = Convert.ToBase64String(ciphertext),
                    HMAC = Convert.ToBase64String(hmacDigest),
                    HMACKey = Convert.ToBase64String(hmac.Key)
                };
            }
            catch (Exception ex)
            {
                logger.Error("Encryption failed. Error: " + ex);
                throw;
            }
        }

        /// <summary>
        /// Decrypts an encrypted payload with HMAC verification
        /// </summary>
        public static byte[] DecryptMessage(byte[] key, EncryptedPayload payload)
        {
            try
            {
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

                using var aes = Aes.Create();
                aes.Key = key;
                aes.IV = iv;

                using var decryptor = aes.CreateDecryptor();
                byte[] decrypted = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);

                // Remove padding
                int paddingLength = decrypted[decrypted.Length - 1];
                Array.Resize(ref decrypted, decrypted.Length - paddingLength);

                logger.Debug($"Message decrypted successfully. Decrypted length: {decrypted.Length}");
                return decrypted;
            }
            catch (Exception ex)
            {
                logger.Error("Decryption failed. Error: " + ex);
                throw;
            }
        }

        private static byte[] GenerateRandomKey(int length)
        {
            using var rng = new RNGCryptoServiceProvider();
            byte[] key = new byte[length];
            rng.GetBytes(key);
            return key;
        }

        private static bool ConstantTimeCompare(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            uint diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
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