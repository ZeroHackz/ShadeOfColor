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
            Console.WriteLine("  shadeofcolor.exe -crypt <inputFile> <outputImage.png> [options]");
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
            Console.WriteLine("  -cover <image>   Hide data inside an existing image (steganography)");
            Console.WriteLine("                   The output will look like the cover image");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  # Basic encoding (creates random-looking image)");
            Console.WriteLine("  shadeofcolor.exe -crypt secret.docx output.png");
            Console.WriteLine();
            Console.WriteLine("  # Encoding with password encryption");
            Console.WriteLine("  shadeofcolor.exe -crypt secret.docx output.png -password mypassword");
            Console.WriteLine();
            Console.WriteLine("  # Steganography: hide data inside a vacation photo");
            Console.WriteLine("  shadeofcolor.exe -crypt secret.docx output.png -cover vacation.png");
            Console.WriteLine();
            Console.WriteLine("  # Steganography with encryption (maximum security)");
            Console.WriteLine("  shadeofcolor.exe -crypt secret.docx output.png -cover photo.png -password");
            Console.WriteLine();
            Console.WriteLine("  # Decryption (auto-detects steganography and encryption)");
            Console.WriteLine("  shadeofcolor.exe -decrypt output.png -password mypassword");
            Console.WriteLine();
            Console.WriteLine("  # View image metadata");
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
                Console.WriteLine("Usage: shadeofcolor.exe -crypt <inputFile> <outputImage.png> [-password [pwd]] [-cover <image>]");
                return;
            }

            string input = args[1];
            string output = args[2];
            string? password = null;
            string? coverImage = null;

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

            // Parse -cover option
            int coverIndex = Array.FindIndex(args, a => a.ToLowerInvariant() == "-cover");
            if (coverIndex >= 0)
            {
                if (coverIndex + 1 < args.Length && !args[coverIndex + 1].StartsWith("-"))
                {
                    coverImage = args[coverIndex + 1];

                    // Verify cover image exists
                    if (!File.Exists(coverImage))
                    {
                        Console.WriteLine($"Error: Cover image not found: {coverImage}");
                        return;
                    }
                }
                else
                {
                    Console.WriteLine("Error: -cover requires an image path.");
                    return;
                }
            }

            FileToImage.EncryptFileToImage(input, output, password, coverImage);

            // Build status message
            var modes = new List<string>();
            if (password != null) modes.Add("encrypted");
            if (coverImage != null) modes.Add("steganographic");

            string modeStr = modes.Count > 0 ? $" ({string.Join(", ", modes)})" : "";
            Console.WriteLine($"OK: '{input}' -> '{output}'{modeStr}");

            if (coverImage != null)
            {
                Console.WriteLine($"    Hidden inside: '{coverImage}'");
            }
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

            // Build status message
            var modes = new List<string>();
            if (info.IsSteganographic) modes.Add("steganographic");
            if (info.IsEncrypted) modes.Add("encrypted");

            string modeStr = modes.Count > 0 ? $" [{string.Join(", ", modes)}]" : "";
            Console.WriteLine($"OK: '{input}'{modeStr} -> '{savedAs}'");
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
            Console.WriteLine($"Steganographic: {(info.IsSteganographic ? "Yes" : "No")}");
            Console.WriteLine($"Original filename: {info.FileName}");
            Console.WriteLine($"Original file size: {FormatFileSize(info.FileSize)}");

            if (info.IsSteganographic && info.DataSize > 0)
            {
                Console.WriteLine($"Embedded data size: {FormatFileSize(info.DataSize)}");
            }
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
