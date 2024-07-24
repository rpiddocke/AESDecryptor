using System;
using System.Security.Cryptography;
using System.Text;

public class AESExample
{
    public static void Main()
    {
        // Encrypted Base64 string and key
        string encryptedBase64 = "ve6A8wHoPCFuIuzP2T8ccv7JKoekDLrGr8UrHloUt8w=";
        string key = "Key";

        try
        {
            // Decrypt the encrypted Base64 string
            string decrypted = AESDecrypt(encryptedBase64, key);
            Console.WriteLine("Decrypted string: " + decrypted);
        }
        catch (Exception ex)
        {
            Console.WriteLine("An error occurred: " + ex.Message);
        }
    }

    public static string AESDecrypt(string encryptedBase64, string key)
    {
        byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);

        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB; // Ensure this matches the encryption mode
            aes.Padding = PaddingMode.PKCS7; // Ensure this matches the padding mode
            aes.Key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(key));

            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            {
                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
    }
}


