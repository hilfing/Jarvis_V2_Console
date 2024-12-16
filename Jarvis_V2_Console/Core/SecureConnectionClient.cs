using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Jarvis_V2_Console.Models;
using Jarvis_V2_Console.Handlers;
using Jarvis_V2_Console.Utils;

namespace Jarvis_V2_Console.Core;

/// <summary>
/// Primary client for secure connection establishment and encrypted communication
/// </summary>
public class SecureConnectionClient
{
    private readonly HttpClient _httpClient;
    private readonly string _baseUrl;
    private KeyExchangeResult? _currentKeyExchangeResult;
    
    private static Logger logger = new Logger("JarvisAI.Core.SecureConnectionClient");

    public SecureConnectionClient(string baseUrl)
    {
        _httpClient = new HttpClient();
        _baseUrl = baseUrl;
        logger.Info($"Secure Connection Client initialized with base URL: {baseUrl}");
    }
    
        /// <summary>
        /// Initiate key exchange with the server
        /// </summary>
        public async Task<KeyExchangeResult> InitiateKeyExchangeAsync()
        {
            try
            {
                logger.Info("Initiating key exchange");

                using var ecdhClient = ECDiffieHellman.Create();
                ecdhClient.GenerateKey(ECCurve.NamedCurves.nistP256);

                var clientPublicKeyBytes = ecdhClient.PublicKey.ExportSubjectPublicKeyInfo();
                var clientPublicKey = Convert.ToBase64String(clientPublicKeyBytes);

                var keyExchangeRequest = new
                {
                    client_public_key = clientPublicKey,
                    client_id = Guid.NewGuid().ToString()
                };
                
                
                logger.Debug($"Sending key exchange request with Client ID: {keyExchangeRequest.client_id}");

                var response = await _httpClient.PostAsJsonAsync($"{_baseUrl}/key-exchange", keyExchangeRequest);
                if (!response.IsSuccessStatusCode)
                {
                    logger.Error("Key exchange request failed. Status Code: " + response.StatusCode);
                    throw new Exception("Status code: " + response.StatusCode);
                }
                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<KeyExchangeResponse>(content);

                byte[] serverPublicKeyBytes = Convert.FromBase64String(result.server_public_key);
                byte[] sharedSecret = CryptoHandler.DeriveSharedSecret(ecdhClient, serverPublicKeyBytes);

                logger.Info("Key exchange completed successfully");
                
                using var importedServerKey = ECDiffieHellman.Create();
                importedServerKey.ImportSubjectPublicKeyInfo(serverPublicKeyBytes, out _);

                return new KeyExchangeResult
                {
                    ClientId = result.client_id,
                    DerivedKey = sharedSecret,
                    ServerPublicKey = importedServerKey.PublicKey
                };
            }
            catch (Exception ex)
            {
                
                logger.Error("Key exchange failed. Error: " + ex.Message);
                throw;
            }
        }

        /// <summary>
        /// Verify connection using encrypted verification message
        /// </summary>
        public async Task<bool> VerifyConnectionAsync(KeyExchangeResult keyExchangeResult)
        {
            try
            {
                logger.Info($"Verifying connection for Client ID: {keyExchangeResult.ClientId}");

                byte[] verificationMessage = Encoding.UTF8.GetBytes("CONNECTION_VERIFICATION_REQUEST");
                var encryptedPayload = CryptoHandler.EncryptMessage(keyExchangeResult.DerivedKey, verificationMessage);

                var verificationRequest = new
                {
                    client_id = keyExchangeResult.ClientId,
                    encrypted_payload = encryptedPayload
                };

                var response = await _httpClient.PostAsJsonAsync($"{_baseUrl}/verify-connection", verificationRequest);
                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<VerificationResponse>(content);

                if (result.status == "verified")
                {
                    try
                    {
                        byte[] decryptedResponse = CryptoHandler.DecryptMessage(
                            keyExchangeResult.DerivedKey, 
                            result.verification_payload
                        );

                        string responseText = Encoding.UTF8.GetString(decryptedResponse);
                        bool isVerified = responseText == "CONNECTION_VERIFIED_SUCCESSFULLY";

                        logger.Info(isVerified 
                            ? "Connection verified successfully" 
                            : "Connection verification failed");

                        return isVerified;
                    }
                    catch (Exception decryptEx)
                    {
                        logger.Debug(decryptEx.StackTrace);
                        logger.Error("Decryption of verification response failed.");
                        return false;
                    }
                }

                logger.Warning($"Connection verification failed. Status: {result.status}");
                return false;
            }
            catch (Exception ex)
            {
                logger.Error("Connection verification process failed. Error: " + ex);
                throw;
            }
        }
    
        /// <summary>
        /// Send encrypted data to a specific endpoint and receive encrypted response
        /// </summary>
        /// <param name="endpoint">Relative endpoint URL</param>
        /// <param name="data">Data to send</param>
        /// <returns>Decrypted response data</returns>
        public async Task<OperationResult<string>> SendEncryptedRequestAsync(string endpoint, object data)
        {
            // Ensure we have an active key exchange
            if (_currentKeyExchangeResult == null)
            {
                logger.Warning("No active key exchange. Initiating key exchange.");
                try 
                {
                    _currentKeyExchangeResult = await InitiateKeyExchangeAsync();
                    bool verified = await VerifyConnectionAsync(_currentKeyExchangeResult);
                    if (!verified)
                    {
                        return OperationResult<string>.Failure("Connection verification failed");
                    }
                }
                catch (Exception ex)
                {
                    logger.Error("Failed to establish secure connection. Error: " + ex);
                    return OperationResult<string>.Failure($"Connection establishment failed: {ex.Message}");
                }
            }

            try 
            {
                // Serialize the data
                string jsonData = JsonSerializer.Serialize(data);
                byte[] messageBytes = Encoding.UTF8.GetBytes(jsonData);

                // Encrypt the data
                var encryptedPayload = CryptoHandler.EncryptMessage(_currentKeyExchangeResult.DerivedKey, messageBytes);

                // Prepare the encrypted request
                var encryptedRequest = new 
                {
                    client_id = _currentKeyExchangeResult.ClientId,
                    encrypted_payload = encryptedPayload
                };

                // Send the encrypted request
                var response = await _httpClient.PostAsJsonAsync($"{_baseUrl}/{endpoint}", encryptedRequest);
                var content = await response.Content.ReadAsStringAsync();

                // Parse the response
                var encryptedResponse = JsonSerializer.Deserialize<VerificationResponse>(content);

                // Check response status
                if (encryptedResponse.status != "verified")
                {
                    logger.Warning($"Encrypted request failed. Status: {encryptedResponse.status}");
                    return OperationResult<string>.Failure($"Request failed with status: {encryptedResponse.status}");
                }

                // Decrypt the response
                byte[] decryptedResponseBytes = CryptoHandler.DecryptMessage(
                    _currentKeyExchangeResult.DerivedKey, 
                    encryptedResponse.verification_payload
                );

                // Convert decrypted bytes to string
                string decryptedResponse = Encoding.UTF8.GetString(decryptedResponseBytes);

                logger.Info("Encrypted request processed successfully");
                return OperationResult<string>.Success(decryptedResponse);
            }
            catch (Exception ex)
            {
                logger.Error("Encrypted request failed. Error: " + ex);

                // Reset key exchange result on persistent failures
                _currentKeyExchangeResult = null;

                return OperationResult<string>.Failure($"Encrypted request failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Invalidate the current key exchange, forcing a new connection
        /// </summary>
        public void InvalidateConnection()
        {
            logger.Info("Invalidating current connection");
            _currentKeyExchangeResult = null;
        }
    }