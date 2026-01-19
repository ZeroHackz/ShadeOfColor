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
        private const byte VersionSteganography = 0x03;

        // Flags
        private const byte FlagEncrypted = 0x01;
        private const byte FlagSteganography = 0x02;

        // PBKDF2 iterations (OWASP recommended minimum for SHA256)
        private const int Pbkdf2Iterations = 100_000;

        // LSB Steganography: bits per channel (1-2 recommended for invisibility)
        private const int BitsPerChannel = 2;

        /// <summary>
        /// Encodes a file into a PNG image, optionally encrypting with a password.
        /// </summary>
        public static void EncryptFileToImage(string inputFile, string outputImage, string? password = null, string? coverImage = null)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFile);
            string fileName = Path.GetFileName(inputFile);

            byte[] data;
            bool isEncrypted = !string.IsNullOrEmpty(password);
            bool useSteganography = !string.IsNullOrEmpty(coverImage);

            if (isEncrypted)
            {
                data = CreateEncryptedData(fileBytes, fileName, password!, useSteganography);
            }
            else
            {
                data = CreateUnencryptedData(fileBytes, fileName, useSteganography);
            }

            if (useSteganography)
            {
                // Embed data into existing cover image using LSB steganography
                EmbedDataInImage(coverImage!, outputImage, data);
            }
            else
            {
                // Create new image from raw data (original behavior)
                CreateImageFromData(outputImage, data);
            }
        }

        /// <summary>
        /// Decodes a PNG image back to the original file, decrypting if necessary.
        /// </summary>
        public static string DecryptImageToFile(string inputImage, string outputPathOrDir, string? password = null)
        {
            using var image = Image.Load<Rgba32>(inputImage);

            // First, try to detect if this is a steganographic image
            var info = GetInfo(inputImage);

            byte[] allBytes;

            if (info.IsSteganographic)
            {
                // Extract data from LSB
                allBytes = ExtractDataFromImage(image, info);
            }
            else
            {
                // Extract raw pixel data (original behavior)
                allBytes = ExtractRawPixelData(image);
            }

            // Detect version from extracted data
            var dataInfo = GetImageInfo(allBytes);

            byte[] fileData;
            string embeddedName;

            if ((dataInfo.Version == VersionEncrypted || dataInfo.Version == VersionSteganography) && dataInfo.IsEncrypted)
            {
                if (string.IsNullOrEmpty(password))
                    throw new Exception("This image is password-protected. Please provide a password with -password.");

                (fileData, embeddedName) = DecryptData(allBytes, password);
            }
            else if (dataInfo.Version == VersionLegacy || 
                     ((dataInfo.Version == VersionEncrypted || dataInfo.Version == VersionSteganography) && !dataInfo.IsEncrypted))
            {
                (fileData, embeddedName) = ExtractUnencryptedData(allBytes, dataInfo.Version);
            }
            else
            {
                throw new Exception($"Unsupported image version: {dataInfo.Version}");
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

            // First check for steganography by trying to extract header from LSB
            var stegoInfo = TryGetSteganographicInfo(image);
            if (stegoInfo.IsValid && stegoInfo.IsSteganographic)
            {
                return stegoInfo;
            }

            // Fall back to raw pixel extraction
            byte[] allBytes = ExtractRawPixelData(image);
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
            public bool IsSteganographic { get; set; }
            public string? FileName { get; set; }
            public long FileSize { get; set; }
            public long DataSize { get; set; }  // Total embedded data size
            public string? ErrorMessage { get; set; }
        }

        #region Private Methods - Image Creation

        private static void CreateImageFromData(string outputImage, byte[] data)
        {
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

        private static void EmbedDataInImage(string coverImagePath, string outputImage, byte[] data)
        {
            using var image = Image.Load<Rgba32>(coverImagePath);

            // Calculate capacity: each pixel can store BitsPerChannel bits per RGB channel (skip alpha for better compatibility)
            // 3 channels * BitsPerChannel bits = bits per pixel
            int bitsPerPixel = 3 * BitsPerChannel;
            long capacityBits = (long)image.Width * image.Height * bitsPerPixel;
            long capacityBytes = capacityBits / 8;

            // We need to store: 4 bytes for data length + actual data
            long requiredBytes = 4 + data.Length;

            if (requiredBytes > capacityBytes)
            {
                throw new Exception($"Cover image too small. Capacity: {capacityBytes:N0} bytes, Required: {requiredBytes:N0} bytes. " +
                                    $"Use a larger image (at least {Math.Ceiling(Math.Sqrt(requiredBytes * 8.0 / bitsPerPixel))}x{Math.Ceiling(Math.Sqrt(requiredBytes * 8.0 / bitsPerPixel))} pixels).");
            }

            // Prepend data length (4 bytes, little-endian)
            byte[] fullData = new byte[4 + data.Length];
            BitConverter.GetBytes(data.Length).CopyTo(fullData, 0);
            Buffer.BlockCopy(data, 0, fullData, 4, data.Length);

            // Convert data to bits
            var bits = BytesToBits(fullData);

            // Embed bits into image using LSB
            int bitIndex = 0;
            byte mask = (byte)((1 << BitsPerChannel) - 1); // e.g., 0b11 for 2 bits

            for (int y = 0; y < image.Height && bitIndex < bits.Length; y++)
            {
                for (int x = 0; x < image.Width && bitIndex < bits.Length; x++)
                {
                    Rgba32 pixel = image[x, y];

                    // Embed in R channel
                    if (bitIndex < bits.Length)
                    {
                        byte value = ExtractBitsFromArray(bits, ref bitIndex, BitsPerChannel);
                        pixel.R = (byte)((pixel.R & ~mask) | value);
                    }

                    // Embed in G channel
                    if (bitIndex < bits.Length)
                    {
                        byte value = ExtractBitsFromArray(bits, ref bitIndex, BitsPerChannel);
                        pixel.G = (byte)((pixel.G & ~mask) | value);
                    }

                    // Embed in B channel
                    if (bitIndex < bits.Length)
                    {
                        byte value = ExtractBitsFromArray(bits, ref bitIndex, BitsPerChannel);
                        pixel.B = (byte)((pixel.B & ~mask) | value);
                    }

                    // Alpha channel is left unchanged for better compatibility
                    image[x, y] = pixel;
                }
            }

            image.Save(outputImage);
        }

        #endregion

        #region Private Methods - Data Extraction

        private static byte[] ExtractRawPixelData(Image<Rgba32> image)
        {
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

            return allBytes;
        }

        private static byte[] ExtractDataFromImage(Image<Rgba32> image, ImageInfo info)
        {
            // First extract the length (4 bytes = 32 bits)
            int bitsPerPixel = 3 * BitsPerChannel;
            int bitsNeededForLength = 32;
            int pixelsNeededForLength = (bitsNeededForLength + bitsPerPixel - 1) / bitsPerPixel;

            var lengthBits = new List<byte>();

            for (int y = 0; y < image.Height && lengthBits.Count < bitsNeededForLength; y++)
            {
                for (int x = 0; x < image.Width && lengthBits.Count < bitsNeededForLength; x++)
                {
                    Rgba32 pixel = image[x, y];

                    // Extract from R
                    for (int b = 0; b < BitsPerChannel && lengthBits.Count < bitsNeededForLength; b++)
                        lengthBits.Add((byte)((pixel.R >> b) & 1));

                    // Extract from G
                    for (int b = 0; b < BitsPerChannel && lengthBits.Count < bitsNeededForLength; b++)
                        lengthBits.Add((byte)((pixel.G >> b) & 1));

                    // Extract from B
                    for (int b = 0; b < BitsPerChannel && lengthBits.Count < bitsNeededForLength; b++)
                        lengthBits.Add((byte)((pixel.B >> b) & 1));
                }
            }

            // Convert length bits to int
            int dataLength = BitsToInt(lengthBits.Take(32).ToArray());

            if (dataLength <= 0 || dataLength > image.Width * image.Height * bitsPerPixel / 8)
            {
                throw new Exception("Invalid data length in steganographic image.");
            }

            // Now extract the actual data
            int totalBitsNeeded = 32 + (dataLength * 8);
            var allBits = new List<byte>();

            for (int y = 0; y < image.Height && allBits.Count < totalBitsNeeded; y++)
            {
                for (int x = 0; x < image.Width && allBits.Count < totalBitsNeeded; x++)
                {
                    Rgba32 pixel = image[x, y];

                    // Extract from R
                    for (int b = 0; b < BitsPerChannel && allBits.Count < totalBitsNeeded; b++)
                        allBits.Add((byte)((pixel.R >> b) & 1));

                    // Extract from G
                    for (int b = 0; b < BitsPerChannel && allBits.Count < totalBitsNeeded; b++)
                        allBits.Add((byte)((pixel.G >> b) & 1));

                    // Extract from B
                    for (int b = 0; b < BitsPerChannel && allBits.Count < totalBitsNeeded; b++)
                        allBits.Add((byte)((pixel.B >> b) & 1));
                }
            }

            // Skip the first 32 bits (length) and convert remaining to bytes
            var dataBits = allBits.Skip(32).Take(dataLength * 8).ToArray();
            return BitsToBytes(dataBits);
        }

        private static ImageInfo TryGetSteganographicInfo(Image<Rgba32> image)
        {
            var info = new ImageInfo();

            try
            {
                // Try to extract enough data for header check
                int bitsPerPixel = 3 * BitsPerChannel;

                // We need at least: 4 bytes (length) + 4 bytes (signature + version + flags) = 64 bits minimum
                int minBitsNeeded = (4 + HeaderLength) * 8;
                long availableBits = (long)image.Width * image.Height * bitsPerPixel;

                if (availableBits < minBitsNeeded)
                {
                    info.IsValid = false;
                    return info;
                }

                // Extract first 4 bytes to get length
                var bits = new List<byte>();
                int bitsToExtract = 32 + (HeaderLength * 8); // Length + full header

                for (int y = 0; y < image.Height && bits.Count < bitsToExtract; y++)
                {
                    for (int x = 0; x < image.Width && bits.Count < bitsToExtract; x++)
                    {
                        Rgba32 pixel = image[x, y];

                        for (int b = 0; b < BitsPerChannel && bits.Count < bitsToExtract; b++)
                            bits.Add((byte)((pixel.R >> b) & 1));

                        for (int b = 0; b < BitsPerChannel && bits.Count < bitsToExtract; b++)
                            bits.Add((byte)((pixel.G >> b) & 1));

                        for (int b = 0; b < BitsPerChannel && bits.Count < bitsToExtract; b++)
                            bits.Add((byte)((pixel.B >> b) & 1));
                    }
                }

                // Get length
                int dataLength = BitsToInt(bits.Take(32).ToArray());

                // Sanity check on length
                if (dataLength <= 0 || dataLength < HeaderLength || dataLength > availableBits / 8)
                {
                    info.IsValid = false;
                    return info;
                }

                // Extract header bytes
                var headerBits = bits.Skip(32).Take(HeaderLength * 8).ToArray();
                byte[] headerBytes = BitsToBytes(headerBits);

                // Check signature
                if (headerBytes.Length >= 2)
                {
                    string signature = Encoding.ASCII.GetString(headerBytes, 0, 2);
                    if (signature == "ER")
                    {
                        info.IsValid = true;
                        info.IsSteganographic = true;

                        byte version = headerBytes[OffsetVersion];
                        info.Version = version;

                        if (version == VersionSteganography || version == VersionEncrypted)
                        {
                            info.IsEncrypted = (headerBytes[OffsetFlags] & FlagEncrypted) != 0;
                            info.FileSize = BitConverter.ToInt64(headerBytes, OffsetFileSize);
                            info.DataSize = dataLength;

                            if (!info.IsEncrypted && headerBytes.Length > OffsetFileName)
                            {
                                info.FileName = Encoding.UTF8.GetString(headerBytes, OffsetFileName, 
                                    Math.Min(FileNameFieldLength, headerBytes.Length - OffsetFileName)).TrimEnd('\0');
                            }
                            else
                            {
                                info.FileName = "(encrypted)";
                            }
                        }

                        return info;
                    }
                }

                info.IsValid = false;
                return info;
            }
            catch
            {
                info.IsValid = false;
                return info;
            }
        }

        #endregion

        #region Private Methods - Data Creation

        private static byte[] CreateEncryptedData(byte[] fileBytes, string fileName, string password, bool forSteganography)
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

                // Version - use steganography version if embedding in cover image
                header[OffsetVersion] = forSteganography ? VersionSteganography : VersionEncrypted;

                // Flags (encrypted + steganography if applicable)
                header[OffsetFlags] = (byte)(FlagEncrypted | (forSteganography ? FlagSteganography : 0));

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

        private static byte[] CreateUnencryptedData(byte[] fileBytes, string fileName, bool forSteganography)
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

            // Build header
            byte[] header = new byte[HeaderLength];

            // Signature "ER"
            header[OffsetSignature] = (byte)'E';
            header[OffsetSignature + 1] = (byte)'R';

            // Version
            header[OffsetVersion] = forSteganography ? VersionSteganography : VersionEncrypted;

            // Flags
            header[OffsetFlags] = forSteganography ? FlagSteganography : (byte)0x00;

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

        #region Private Methods - Decryption

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

            // V2/V3 unencrypted format
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

            byte potentialVersion = allBytes[2];

            if ((potentialVersion == VersionEncrypted || potentialVersion == VersionSteganography) && allBytes.Length >= HeaderLength)
            {
                // V2/V3 format
                info.Version = potentialVersion;
                byte flags = allBytes[OffsetFlags];
                info.IsEncrypted = (flags & FlagEncrypted) != 0;
                info.IsSteganographic = (flags & FlagSteganography) != 0;
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
                info.IsSteganographic = false;
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

        #region Private Methods - Bit Manipulation

        private static byte[] BytesToBits(byte[] bytes)
        {
            var bits = new byte[bytes.Length * 8];
            for (int i = 0; i < bytes.Length; i++)
            {
                for (int b = 0; b < 8; b++)
                {
                    bits[i * 8 + b] = (byte)((bytes[i] >> b) & 1);
                }
            }
            return bits;
        }

        private static byte[] BitsToBytes(byte[] bits)
        {
            int byteCount = bits.Length / 8;
            var bytes = new byte[byteCount];
            for (int i = 0; i < byteCount; i++)
            {
                byte value = 0;
                for (int b = 0; b < 8; b++)
                {
                    if (bits[i * 8 + b] == 1)
                        value |= (byte)(1 << b);
                }
                bytes[i] = value;
            }
            return bytes;
        }

        private static int BitsToInt(byte[] bits)
        {
            int value = 0;
            for (int i = 0; i < 32 && i < bits.Length; i++)
            {
                if (bits[i] == 1)
                    value |= (1 << i);
            }
            return value;
        }

        private static byte ExtractBitsFromArray(byte[] bits, ref int index, int count)
        {
            byte value = 0;
            for (int i = 0; i < count && index < bits.Length; i++)
            {
                if (bits[index++] == 1)
                    value |= (byte)(1 << i);
            }
            return value;
        }

        #endregion
    }
}
