using System.Security.Cryptography;
using System.Text;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

namespace ShadeOfColor
{
    public static class FileToImage
    {
        // Header field sizes
        private const int SignatureLength = 2;          // "ER"
        private const int VersionLength = 1;            // Version byte
        private const int FlagsLength = 1;              // Flags byte
        private const int SaltLength = 16;              // PBKDF2 salt
        private const int NonceLength = 12;             // AES-GCM nonce
        private const int FileSizeLength = 8;           // int64
        private const int FileNameFieldLength = 256;    // UTF-8 filename
        private const int Sha1Length = 20;              // SHA1 hash
        private const int AuthTagLength = 16;           // AES-GCM auth tag

        // Header layout offsets
        private const int OffsetSignature = 0;
        private const int OffsetVersion = 2;
        private const int OffsetFlags = 3;
        private const int OffsetSalt = 4;
        private const int OffsetNonce = 20;
        private const int OffsetFileSize = 32;
        private const int OffsetFileName = 40;
        private const int OffsetSha1 = 296;
        private const int OffsetAuthTag = 316;

        // Total header size: 332 bytes
        private const int HeaderLength = SignatureLength + VersionLength + FlagsLength +
                                         SaltLength + NonceLength + FileSizeLength +
                                         FileNameFieldLength + Sha1Length + AuthTagLength;

        // Legacy header size (v1): 286 bytes
        private const int LegacyHeaderLength = 2 + 8 + 256 + 20;

        // Versions
        private const byte VersionLegacy = 0x01;
        private const byte VersionEncrypted = 0x02;

        // Flags
        private const byte FlagEncrypted = 0x01;

        // PBKDF2 iterations (OWASP recommended minimum for SHA256)
        private const int Pbkdf2Iterations = 100_000;

        /// <summary>
        /// Encodes a file into a PNG image, optionally encrypting with a password.
        /// </summary>
        public static void EncryptFileToImage(string inputFile, string outputImage, string? password = null)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFile);
            string fileName = Path.GetFileName(inputFile);

            byte[] data;
            if (!string.IsNullOrEmpty(password))
            {
                data = CreateEncryptedData(fileBytes, fileName, password);
            }
            else
            {
                data = CreateUnencryptedData(fileBytes, fileName);
            }

            // pixel RGBA -> 4 bytes per pixel
            int size = (int)Math.Ceiling(Math.Sqrt(data.Length / 4.0));
            using var image = new Image<Rgba32>(size, size);

            int i = 0;
            for (int y = 0; y < size; y++)
            {
                for (int x = 0; x < size; x++)
                {
                    byte r = i < data.Length ? data[i++] : (byte)0;
                    byte g = i < data.Length ? data[i++] : (byte)0;
                    byte b = i < data.Length ? data[i++] : (byte)0;
                    byte a = i < data.Length ? data[i++] : (byte)255;
                    image[x, y] = new Rgba32(r, g, b, a);
                }
            }

            image.Save(outputImage);
        }

        /// <summary>
        /// Decodes a PNG image back to the original file, decrypting if necessary.
        /// </summary>
        public static string DecryptImageToFile(string inputImage, string outputPathOrDir, string? password = null)
        {
            using var image = Image.Load<Rgba32>(inputImage);

            int capacity = checked(image.Width * image.Height * 4);
            byte[] allBytes = new byte[capacity];

            int i = 0;
            for (int y = 0; y < image.Height; y++)
            {
                for (int x = 0; x < image.Width; x++)
                {
                    Rgba32 p = image[x, y];
                    allBytes[i++] = p.R;
                    allBytes[i++] = p.G;
                    allBytes[i++] = p.B;
                    allBytes[i++] = p.A;
                }
            }

            // Detect version
            var info = GetImageInfo(allBytes);

            byte[] fileData;
            string embeddedName;

            if (info.Version == VersionEncrypted && info.IsEncrypted)
            {
                if (string.IsNullOrEmpty(password))
                    throw new Exception("This image is password-protected. Please provide a password with -password.");

                (fileData, embeddedName) = DecryptData(allBytes, password);
            }
            else if (info.Version == VersionLegacy || (info.Version == VersionEncrypted && !info.IsEncrypted))
            {
                (fileData, embeddedName) = ExtractUnencryptedData(allBytes, info.Version);
            }
            else
            {
                throw new Exception($"Unsupported image version: {info.Version}");
            }

            string outputPath = ResolveOutputPath(outputPathOrDir, embeddedName);
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            File.WriteAllBytes(outputPath, fileData);

            return outputPath;
        }

        /// <summary>
        /// Gets metadata about an encoded image without extracting the file.
        /// </summary>
        public static ImageInfo GetInfo(string inputImage)
        {
            using var image = Image.Load<Rgba32>(inputImage);

            int capacity = checked(image.Width * image.Height * 4);
            byte[] allBytes = new byte[capacity];

            int i = 0;
            for (int y = 0; y < image.Height; y++)
            {
                for (int x = 0; x < image.Width; x++)
                {
                    Rgba32 p = image[x, y];
                    allBytes[i++] = p.R;
                    allBytes[i++] = p.G;
                    allBytes[i++] = p.B;
                    allBytes[i++] = p.A;
                }
            }

            return GetImageInfo(allBytes);
        }

        /// <summary>
        /// Information about an encoded image.
        /// </summary>
        public class ImageInfo
        {
            public bool IsValid { get; set; }
            public byte Version { get; set; }
            public bool IsEncrypted { get; set; }
            public string? FileName { get; set; }
            public long FileSize { get; set; }
            public string? ErrorMessage { get; set; }
        }

        #region Private Methods - Data Creation

        private static byte[] CreateEncryptedData(byte[] fileBytes, string fileName, string password)
        {
            // Generate random salt and nonce
            byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceLength);

            // Derive key using PBKDF2-SHA256
            byte[] key = DeriveKey(password, salt);

            try
            {
                // Compute SHA1 of original file
                byte[] sha1Hash;
                using (var sha1 = SHA1.Create())
                {
                    sha1Hash = sha1.ComputeHash(fileBytes);
                }

                // Validate filename length
                if (Encoding.UTF8.GetByteCount(fileName) > FileNameFieldLength)
                    throw new Exception($"Filename too long (max {FileNameFieldLength} UTF-8 bytes).");

                // Create plaintext: filename (256) + sha1 (20) + filedata
                byte[] plaintext = new byte[FileNameFieldLength + Sha1Length + fileBytes.Length];
                byte[] nameBytes = Encoding.UTF8.GetBytes(fileName);
                nameBytes.CopyTo(plaintext, 0);
                sha1Hash.CopyTo(plaintext, FileNameFieldLength);
                Buffer.BlockCopy(fileBytes, 0, plaintext, FileNameFieldLength + Sha1Length, fileBytes.Length);

                // Encrypt with AES-GCM
                byte[] ciphertext = new byte[plaintext.Length];
                byte[] authTag = new byte[AuthTagLength];

                using (var aesGcm = new AesGcm(key, AuthTagLength))
                {
                    aesGcm.Encrypt(nonce, plaintext, ciphertext, authTag);
                }

                // Build header
                byte[] header = new byte[HeaderLength];

                // Signature "ER"
                header[OffsetSignature] = (byte)'E';
                header[OffsetSignature + 1] = (byte)'R';

                // Version
                header[OffsetVersion] = VersionEncrypted;

                // Flags (encrypted)
                header[OffsetFlags] = FlagEncrypted;

                // Salt
                Buffer.BlockCopy(salt, 0, header, OffsetSalt, SaltLength);

                // Nonce
                Buffer.BlockCopy(nonce, 0, header, OffsetNonce, NonceLength);

                // File size
                BitConverter.GetBytes(fileBytes.LongLength).CopyTo(header, OffsetFileSize);

                // Filename field (zeros for encrypted - stored in ciphertext)
                // Already zeros

                // SHA1 field (zeros for encrypted - stored in ciphertext)
                // Already zeros

                // Auth tag
                Buffer.BlockCopy(authTag, 0, header, OffsetAuthTag, AuthTagLength);

                // Combine header + ciphertext
                byte[] data = new byte[header.Length + ciphertext.Length];
                Buffer.BlockCopy(header, 0, data, 0, header.Length);
                Buffer.BlockCopy(ciphertext, 0, data, header.Length, ciphertext.Length);

                return data;
            }
            finally
            {
                // Clear sensitive data
                CryptographicOperations.ZeroMemory(key);
            }
        }

        private static byte[] CreateUnencryptedData(byte[] fileBytes, string fileName)
        {
            // Compute SHA1
            byte[] sha1Hash;
            using (var sha1 = SHA1.Create())
            {
                sha1Hash = sha1.ComputeHash(fileBytes);
            }

            // Validate filename length
            if (Encoding.UTF8.GetByteCount(fileName) > FileNameFieldLength)
                throw new Exception($"Filename too long (max {FileNameFieldLength} UTF-8 bytes).");

            // Build header (v2 format but unencrypted)
            byte[] header = new byte[HeaderLength];

            // Signature "ER"
            header[OffsetSignature] = (byte)'E';
            header[OffsetSignature + 1] = (byte)'R';

            // Version
            header[OffsetVersion] = VersionEncrypted; // Use v2 format

            // Flags (not encrypted)
            header[OffsetFlags] = 0x00;

            // Salt, Nonce - zeros (not used)
            // Already zeros

            // File size
            BitConverter.GetBytes(fileBytes.LongLength).CopyTo(header, OffsetFileSize);

            // Filename
            byte[] nameBytes = Encoding.UTF8.GetBytes(fileName);
            Buffer.BlockCopy(nameBytes, 0, header, OffsetFileName, nameBytes.Length);

            // SHA1
            Buffer.BlockCopy(sha1Hash, 0, header, OffsetSha1, Sha1Length);

            // Auth tag - zeros (not used)
            // Already zeros

            // Combine header + file data
            byte[] data = new byte[header.Length + fileBytes.Length];
            Buffer.BlockCopy(header, 0, data, 0, header.Length);
            Buffer.BlockCopy(fileBytes, 0, data, header.Length, fileBytes.Length);

            return data;
        }

        #endregion

        #region Private Methods - Data Extraction

        private static (byte[] fileData, string fileName) DecryptData(byte[] allBytes, string password)
        {
            if (allBytes.Length < HeaderLength)
                throw new Exception("Insufficient data for header.");

            // Extract header fields
            byte[] salt = new byte[SaltLength];
            Buffer.BlockCopy(allBytes, OffsetSalt, salt, 0, SaltLength);

            byte[] nonce = new byte[NonceLength];
            Buffer.BlockCopy(allBytes, OffsetNonce, nonce, 0, NonceLength);

            long fileSize = BitConverter.ToInt64(allBytes, OffsetFileSize);
            if (fileSize < 0)
                throw new Exception("Invalid file size in header.");

            byte[] authTag = new byte[AuthTagLength];
            Buffer.BlockCopy(allBytes, OffsetAuthTag, authTag, 0, AuthTagLength);

            // Calculate ciphertext length
            int ciphertextLength = FileNameFieldLength + Sha1Length + (int)fileSize;
            if (HeaderLength + ciphertextLength > allBytes.Length)
                throw new Exception("Image does not contain all declared data.");

            byte[] ciphertext = new byte[ciphertextLength];
            Buffer.BlockCopy(allBytes, HeaderLength, ciphertext, 0, ciphertextLength);

            // Derive key
            byte[] key = DeriveKey(password, salt);

            try
            {
                // Decrypt
                byte[] plaintext = new byte[ciphertextLength];

                using (var aesGcm = new AesGcm(key, AuthTagLength))
                {
                    try
                    {
                        aesGcm.Decrypt(nonce, ciphertext, authTag, plaintext);
                    }
                    catch (AuthenticationTagMismatchException)
                    {
                        throw new Exception("Invalid password or corrupted data.");
                    }
                }

                // Extract filename
                string fileName = Encoding.UTF8.GetString(plaintext, 0, FileNameFieldLength).TrimEnd('\0');

                // Extract SHA1
                byte[] sha1Stored = new byte[Sha1Length];
                Buffer.BlockCopy(plaintext, FileNameFieldLength, sha1Stored, 0, Sha1Length);

                // Extract file data
                byte[] fileData = new byte[fileSize];
                Buffer.BlockCopy(plaintext, FileNameFieldLength + Sha1Length, fileData, 0, (int)fileSize);

                // Verify SHA1
                using var sha1 = SHA1.Create();
                byte[] sha1Calc = sha1.ComputeHash(fileData);
                if (!CryptographicOperations.FixedTimeEquals(sha1Stored, sha1Calc))
                    throw new Exception("SHA1 mismatch: data corrupted or altered.");

                return (fileData, fileName);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        private static (byte[] fileData, string fileName) ExtractUnencryptedData(byte[] allBytes, byte version)
        {
            if (version == VersionLegacy)
            {
                return ExtractLegacyData(allBytes);
            }

            // V2 unencrypted format
            if (allBytes.Length < HeaderLength)
                throw new Exception("Insufficient data for header.");

            long fileSize = BitConverter.ToInt64(allBytes, OffsetFileSize);
            if (fileSize < 0)
                throw new Exception("Invalid file size in header.");

            string fileName = Encoding.UTF8.GetString(allBytes, OffsetFileName, FileNameFieldLength).TrimEnd('\0');

            byte[] sha1Stored = new byte[Sha1Length];
            Buffer.BlockCopy(allBytes, OffsetSha1, sha1Stored, 0, Sha1Length);

            if (HeaderLength + fileSize > allBytes.Length)
                throw new Exception("Image does not contain all declared data.");

            byte[] fileData = new byte[fileSize];
            Buffer.BlockCopy(allBytes, HeaderLength, fileData, 0, (int)fileSize);

            // Verify SHA1
            using var sha1 = SHA1.Create();
            byte[] sha1Calc = sha1.ComputeHash(fileData);
            if (!CryptographicOperations.FixedTimeEquals(sha1Stored, sha1Calc))
                throw new Exception("SHA1 mismatch: data corrupted or altered.");

            return (fileData, fileName);
        }

        private static (byte[] fileData, string fileName) ExtractLegacyData(byte[] allBytes)
        {
            // Legacy v1 format (286 byte header)
            if (allBytes.Length < LegacyHeaderLength)
                throw new Exception("Insufficient data for legacy header.");

            long fileSize = BitConverter.ToInt64(allBytes, 2);
            if (fileSize < 0)
                throw new Exception("Invalid file size in header.");

            string fileName = Encoding.UTF8.GetString(allBytes, 10, 256).TrimEnd('\0');

            byte[] sha1Stored = new byte[Sha1Length];
            Buffer.BlockCopy(allBytes, 10 + 256, sha1Stored, 0, Sha1Length);

            if (LegacyHeaderLength + fileSize > allBytes.Length)
                throw new Exception("Image does not contain all declared data.");

            byte[] fileData = new byte[fileSize];
            Buffer.BlockCopy(allBytes, LegacyHeaderLength, fileData, 0, (int)fileSize);

            // Verify SHA1
            using var sha1 = SHA1.Create();
            byte[] sha1Calc = sha1.ComputeHash(fileData);
            if (!CryptographicOperations.FixedTimeEquals(sha1Stored, sha1Calc))
                throw new Exception("SHA1 mismatch: data corrupted or altered.");

            return (fileData, fileName);
        }

        #endregion

        #region Private Methods - Utilities

        private static ImageInfo GetImageInfo(byte[] allBytes)
        {
            var info = new ImageInfo();

            // Check minimum size for signature
            if (allBytes.Length < 2)
            {
                info.IsValid = false;
                info.ErrorMessage = "Data too small.";
                return info;
            }

            // Check signature
            string signature = Encoding.ASCII.GetString(allBytes, 0, 2);
            if (signature != "ER")
            {
                info.IsValid = false;
                info.ErrorMessage = "Invalid signature: not a ShadeOfColor image.";
                return info;
            }

            info.IsValid = true;

            // Detect version - check if byte at position 2 looks like a version byte
            // In legacy format, position 2 is the start of file size (int64)
            // If byte 2 is 0x01 or 0x02 and bytes 3-9 look like they could be part of new format,
            // we need a heuristic. Check if position 2 contains a valid version.

            // Legacy format: bytes 2-9 are file size (int64 little-endian)
            // New format: byte 2 is version (0x02), byte 3 is flags

            byte potentialVersion = allBytes[2];

            if (potentialVersion == VersionEncrypted && allBytes.Length >= HeaderLength)
            {
                // V2 format
                info.Version = VersionEncrypted;
                info.IsEncrypted = (allBytes[OffsetFlags] & FlagEncrypted) != 0;
                info.FileSize = BitConverter.ToInt64(allBytes, OffsetFileSize);

                if (!info.IsEncrypted)
                {
                    info.FileName = Encoding.UTF8.GetString(allBytes, OffsetFileName, FileNameFieldLength).TrimEnd('\0');
                }
                else
                {
                    info.FileName = "(encrypted)";
                }
            }
            else if (allBytes.Length >= LegacyHeaderLength)
            {
                // Legacy format
                info.Version = VersionLegacy;
                info.IsEncrypted = false;
                info.FileSize = BitConverter.ToInt64(allBytes, 2);
                info.FileName = Encoding.UTF8.GetString(allBytes, 10, 256).TrimEnd('\0');
            }
            else
            {
                info.IsValid = false;
                info.ErrorMessage = "Insufficient data for header.";
            }

            return info;
        }

        private static byte[] DeriveKey(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256);

            return pbkdf2.GetBytes(32); // 256 bits
        }

        private static string ResolveOutputPath(string outputPathOrDir, string embeddedName)
        {
            bool endsWithSep =
                outputPathOrDir.EndsWith(Path.DirectorySeparatorChar) ||
                outputPathOrDir.EndsWith(Path.AltDirectorySeparatorChar);

            if (endsWithSep || Directory.Exists(outputPathOrDir))
            {
                return Path.Combine(outputPathOrDir, embeddedName);
            }

            return outputPathOrDir;
        }

        #endregion
    }
}
