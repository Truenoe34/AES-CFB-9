using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        string originalText = "Секретне повідомлення для перевірки AES у режимі CFB!";

        using (Aes aes = Aes.Create())
        {
            // Обираємо режим CFB замість CBC
            aes.Mode = CipherMode.CFB;
            aes.FeedbackSize = 128; // Розмір зворотного зв'язку 128 біт (розмір блоку AES)
            aes.Padding = PaddingMode.PKCS7;

            // Генеруємо випадкові ключ (256 біт) та вектор ініціалізації (128 біт)
            aes.GenerateKey();
            aes.GenerateIV();

            Console.WriteLine($"Режим шифрування: {aes.Mode}");
            Console.WriteLine($"Ключ (Base64): {Convert.ToBase64String(aes.Key)}");
            Console.WriteLine($"IV (Base64):   {Convert.ToBase64String(aes.IV)}");
            Console.WriteLine($"Оригінал:      {originalText}\n");

            // Зашифрування
            byte[] encryptedBytes = EncryptString(originalText, aes.Key, aes.IV);
            Console.WriteLine($"Зашифровано (Base64): {Convert.ToBase64String(encryptedBytes)}");

            // Розшифрування
            string decryptedText = DecryptString(encryptedBytes, aes.Key, aes.IV);
            Console.WriteLine($"Розшифровано:         {decryptedText}");
        }
    }

    static byte[] EncryptString(string plainText, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.CFB;
            aes.FeedbackSize = 128;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            using (MemoryStream ms = new MemoryStream())
            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                cs.Write(plainBytes, 0, plainBytes.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }
    }

    static string DecryptString(byte[] cipherBytes, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.CFB;
            aes.FeedbackSize = 128;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            using (MemoryStream ms = new MemoryStream(cipherBytes))
            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (StreamReader reader = new StreamReader(cs, Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
