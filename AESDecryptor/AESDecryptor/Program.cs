using System;
using System.Security.Cryptography;
using System.Text;

namespace AESEncryptionApp
{
    class Program
    {
        private const int CRYPT_OK = 0;
        private const int CRYPT_ERROR = -1;

        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("Usage: AESEncryptionApp <encrypt|decrypt> <value> <encryption key>");
                return;
            }

            string action = args[0];
            string value = args[1];
            string encryptionKey = args[2];

            if (action.ToLower() == "encrypt")
            {
                string encryptedValue;
                int result = AESEncrypt(value, out encryptedValue, encryptionKey);

                if (result == CRYPT_OK)
                {
                    Console.WriteLine("Encrypted value: " + encryptedValue);
                }
                else
                {
                    Console.WriteLine("Encryption failed.");
                }
            }
            else if (action.ToLower() == "decrypt")
            {
                string decryptedValue;
                int result = AESDecrypt(value, out decryptedValue, encryptionKey);

                if (result == CRYPT_OK)
                {
                    Console.WriteLine("Decrypted value: " + decryptedValue);
                }
                else
                {
                    Console.WriteLine("Decryption failed.");
                }
            }
            else
            {
                Console.WriteLine("Invalid action. Use 'encrypt' or 'decrypt'.");
            }
        }

        public static int AESEncrypt(string lpwszSource, out string lpwszDest, string lpwszKey)
        {
            lpwszDest = string.Empty;

            try
            {
                // Hash the encryption key using SHA-256
                byte[] keyHash;
                using (SHA256 sha256 = SHA256.Create())
                {
                    keyHash = sha256.ComputeHash(Encoding.Unicode.GetBytes(lpwszKey));
                }

                // Encrypt lpwszSource with AES in ECB mode
                byte[] encrypted;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = keyHash;
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.Zeros;

                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    byte[] sourceBytes = Encoding.Unicode.GetBytes(lpwszSource);
                    encrypted = encryptor.TransformFinalBlock(sourceBytes, 0, sourceBytes.Length);
                }

                // Base64 encode the encrypted data
                string base64Encoded = Convert.ToBase64String(encrypted);

                lpwszDest = base64Encoded;
                return CRYPT_OK;
            }
            catch
            {
                return CRYPT_ERROR;
            }
        }

        public static int AESDecrypt(string lpwszSource, out string lpwszDest, string lpwszKey)
        {
            lpwszDest = string.Empty;

            try
            {
                // Hash the encryption key using SHA-256
                byte[] keyHash;
                using (SHA256 sha256 = SHA256.Create())
                {
                    keyHash = sha256.ComputeHash(Encoding.Unicode.GetBytes(lpwszKey));
                }

                // Base64 decode the encrypted data
                byte[] encryptedBytes = Convert.FromBase64String(lpwszSource);

                // Decrypt lpwszSource with AES in ECB mode
                byte[] decrypted;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = keyHash;
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.Zeros;

                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    decrypted = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                }

                // Convert decrypted bytes back to string
                lpwszDest = Encoding.Unicode.GetString(decrypted);
                return CRYPT_OK;
            }
            catch
            {
                return CRYPT_ERROR;
            }
        }
    }
}



