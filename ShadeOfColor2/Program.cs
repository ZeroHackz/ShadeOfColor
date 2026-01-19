using System;

namespace ShadeOfColor
{
    class Program
    {
        static void Help()
        {
            Console.WriteLine("ShadeOfColor - Turn any file into an image, and back again.");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  shadeofcolor.exe -crypt <inputFile> <outputImage.png> [-password [pwd]]");
            Console.WriteLine("  shadeofcolor.exe -decrypt <inputImage.png> [-password [pwd]]");
            Console.WriteLine("  shadeofcolor.exe -info <inputImage.png>");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  -crypt    Encode a file into a PNG image");
            Console.WriteLine("  -decrypt  Decode a PNG image back to the original file");
            Console.WriteLine("  -info     Display metadata about an encoded image");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  -password [pwd]  Encrypt/decrypt with a password");
            Console.WriteLine("                   If password is omitted, you will be prompted securely");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  shadeofcolor.exe -crypt secret.docx output.png -password mypassword");
            Console.WriteLine("  shadeofcolor.exe -crypt secret.docx output.png -password");
            Console.WriteLine("  shadeofcolor.exe -decrypt output.png -password mypassword");
            Console.WriteLine("  shadeofcolor.exe -info output.png");
        }

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Help();
                return;
            }

            string command = args[0].ToLowerInvariant();

            try
            {
                switch (command)
                {
                    case "-crypt":
                        HandleCrypt(args);
                        break;

                    case "-decrypt":
                        HandleDecrypt(args);
                        break;

                    case "-info":
                        HandleInfo(args);
                        break;

                    case "-help":
                    case "--help":
                    case "/?":
                        Help();
                        break;

                    default:
                        Console.WriteLine($"Unknown command: {command}");
                        Console.WriteLine("Use -help to see available commands.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static void HandleCrypt(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: shadeofcolor.exe -crypt <inputFile> <outputImage.png> [-password [pwd]]");
                return;
            }

            string input = args[1];
            string output = args[2];
            string? password = null;

            // Parse -password option
            int passwordIndex = Array.FindIndex(args, a => a.ToLowerInvariant() == "-password");
            if (passwordIndex >= 0)
            {
                if (passwordIndex + 1 < args.Length && !args[passwordIndex + 1].StartsWith("-"))
                {
                    // Password provided as argument
                    password = args[passwordIndex + 1];
                }
                else
                {
                    // Prompt for password
                    password = ReadPasswordSecurely("Enter password: ");
                    if (string.IsNullOrEmpty(password))
                    {
                        Console.WriteLine("Error: Password cannot be empty.");
                        return;
                    }

                    // Confirm password
                    string confirm = ReadPasswordSecurely("Confirm password: ");
                    if (password != confirm)
                    {
                        Console.WriteLine("Error: Passwords do not match.");
                        return;
                    }
                }
            }

            FileToImage.EncryptFileToImage(input, output, password);

            string mode = password != null ? " (encrypted)" : "";
            Console.WriteLine($"OK: '{input}' -> '{output}'{mode}");
        }

        static void HandleDecrypt(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: shadeofcolor.exe -decrypt <inputImage.png> [-password [pwd]]");
                return;
            }

            string input = args[1];
            string? password = null;

            // Check if image is encrypted
            var info = FileToImage.GetInfo(input);
            if (!info.IsValid)
            {
                Console.WriteLine($"Error: {info.ErrorMessage}");
                return;
            }

            // Parse -password option
            int passwordIndex = Array.FindIndex(args, a => a.ToLowerInvariant() == "-password");
            if (passwordIndex >= 0)
            {
                if (passwordIndex + 1 < args.Length && !args[passwordIndex + 1].StartsWith("-"))
                {
                    password = args[passwordIndex + 1];
                }
                else
                {
                    password = ReadPasswordSecurely("Enter password: ");
                }
            }
            else if (info.IsEncrypted)
            {
                // Image is encrypted but no -password flag provided
                Console.WriteLine("This image is password-protected.");
                password = ReadPasswordSecurely("Enter password: ");
            }

            string savedAs = FileToImage.DecryptImageToFile(input, Directory.GetCurrentDirectory(), password);
            Console.WriteLine($"OK: '{input}' -> '{savedAs}'");
        }

        static void HandleInfo(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: shadeofcolor.exe -info <inputImage.png>");
                return;
            }

            string input = args[1];
            var info = FileToImage.GetInfo(input);

            Console.WriteLine($"File: {input}");
            Console.WriteLine($"Valid ShadeOfColor image: {(info.IsValid ? "Yes" : "No")}");

            if (!info.IsValid)
            {
                Console.WriteLine($"Error: {info.ErrorMessage}");
                return;
            }

            Console.WriteLine($"Version: {info.Version}");
            Console.WriteLine($"Encrypted: {(info.IsEncrypted ? "Yes" : "No")}");
            Console.WriteLine($"Original filename: {info.FileName}");
            Console.WriteLine($"Original file size: {FormatFileSize(info.FileSize)}");
        }

        static string ReadPasswordSecurely(string prompt)
        {
            Console.Write(prompt);

            var password = new System.Text.StringBuilder();

            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(intercept: true);

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }
                else if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Remove(password.Length - 1, 1);
                        Console.Write("\b \b");
                    }
                }
                else if (key.Key == ConsoleKey.Escape)
                {
                    // Clear and return empty
                    Console.WriteLine();
                    return string.Empty;
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    password.Append(key.KeyChar);
                    Console.Write("*");
                }
            }

            return password.ToString();
        }

        static string FormatFileSize(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int suffixIndex = 0;
            double size = bytes;

            while (size >= 1024 && suffixIndex < suffixes.Length - 1)
            {
                size /= 1024;
                suffixIndex++;
            }

            return $"{size:0.##} {suffixes[suffixIndex]} ({bytes:N0} bytes)";
        }
    }
}
