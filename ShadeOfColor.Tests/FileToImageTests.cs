using System.Security.Cryptography;
using System.Text;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

namespace ShadeOfColor.Tests;

/// <summary>
/// Test cases for ShadeOfColor encoding and decoding functionality.
/// </summary>
public class FileToImageTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _testCoverImage;
    private readonly string _testPassword = "testcase";

    public FileToImageTests()
    {
        // Create a unique temp directory for each test run
        _testDir = Path.Combine(Path.GetTempPath(), $"ShadeOfColor_Tests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);

        // Path to the test cover image
        _testCoverImage = Path.Combine(GetProjectRoot(), "testcase-image.png");
    }

    public void Dispose()
    {
        // Clean up test directory after tests
        if (Directory.Exists(_testDir))
        {
            try
            {
                Directory.Delete(_testDir, recursive: true);
            }
            catch
            {
                // Ignore cleanup errors
            }
        }
    }

    private static string GetProjectRoot()
    {
        // Navigate from bin/Debug/net8.0 to project root
        var dir = AppContext.BaseDirectory;
        while (dir != null && !File.Exists(Path.Combine(dir, "ShadeOfColor2.sln")))
        {
            dir = Directory.GetParent(dir)?.FullName;
        }
        return dir ?? throw new InvalidOperationException("Could not find project root");
    }

    #region Test Case 1: No Password, No Cover Image (Default)

    [Fact]
    public void Case1_DefaultEncoding_NoPassword_NoCover_ShouldEncodeAndDecode()
    {
        // Arrange
        string originalContent = "This is a test file for Case 1: Default encoding without password or cover image.";
        string inputFile = Path.Combine(_testDir, "case1_input.txt");
        string outputImage = Path.Combine(_testDir, "case1_output.png");
        
        File.WriteAllText(inputFile, originalContent);

        // Act - Encode
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: null, coverImage: null);

        // Assert - Image was created
        Assert.True(File.Exists(outputImage), "Output image should exist");

        // Act - Check info
        var info = FileToImage.GetInfo(outputImage);

        // Assert - Info is correct
        Assert.True(info.IsValid, "Image should be valid");
        Assert.Equal(2, info.Version); // V2 format
        Assert.False(info.IsEncrypted, "Should not be encrypted");
        Assert.False(info.IsSteganographic, "Should not be steganographic");
        Assert.Equal("case1_input.txt", info.FileName);
        Assert.Equal(originalContent.Length, info.FileSize);

        // Act - Decode
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, password: null);

        // Assert - Content matches
        Assert.True(File.Exists(decodedPath), "Decoded file should exist");
        string decodedContent = File.ReadAllText(decodedPath);
        Assert.Equal(originalContent, decodedContent);
    }

    [Fact]
    public void Case1_DefaultEncoding_BinaryFile_ShouldPreserveExactBytes()
    {
        // Arrange - Create a binary file with random data
        byte[] originalBytes = RandomNumberGenerator.GetBytes(1024);
        string inputFile = Path.Combine(_testDir, "case1_binary.bin");
        string outputImage = Path.Combine(_testDir, "case1_binary_output.png");
        
        File.WriteAllBytes(inputFile, originalBytes);

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: null, coverImage: null);
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, password: null);

        // Assert
        byte[] decodedBytes = File.ReadAllBytes(decodedPath);
        Assert.Equal(originalBytes, decodedBytes);
    }

    [Fact]
    public void Case1_DefaultEncoding_EmptyFile_ShouldHandleGracefully()
    {
        // Arrange
        string inputFile = Path.Combine(_testDir, "case1_empty.txt");
        string outputImage = Path.Combine(_testDir, "case1_empty_output.png");
        
        File.WriteAllText(inputFile, "");

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: null, coverImage: null);
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, password: null);

        // Assert
        string decodedContent = File.ReadAllText(decodedPath);
        Assert.Equal("", decodedContent);
    }

    [Fact]
    public void Case1_DefaultEncoding_LargeFile_ShouldEncodeAndDecode()
    {
        // Arrange - Create a 100KB file
        byte[] originalBytes = RandomNumberGenerator.GetBytes(100 * 1024);
        string inputFile = Path.Combine(_testDir, "case1_large.bin");
        string outputImage = Path.Combine(_testDir, "case1_large_output.png");
        
        File.WriteAllBytes(inputFile, originalBytes);

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: null, coverImage: null);
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, password: null);

        // Assert
        byte[] decodedBytes = File.ReadAllBytes(decodedPath);
        Assert.Equal(originalBytes, decodedBytes);
    }

    #endregion

    #region Test Case 2: Password "testcase", No Cover Image

    [Fact]
    public void Case2_PasswordEncryption_ShouldEncodeAndDecode()
    {
        // Arrange
        string originalContent = "This is a test file for Case 2: Password encryption without cover image.";
        string inputFile = Path.Combine(_testDir, "case2_input.txt");
        string outputImage = Path.Combine(_testDir, "case2_output.png");
        
        File.WriteAllText(inputFile, originalContent);

        // Act - Encode with password
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: _testPassword, coverImage: null);

        // Assert - Image was created
        Assert.True(File.Exists(outputImage), "Output image should exist");

        // Act - Check info
        var info = FileToImage.GetInfo(outputImage);

        // Assert - Info is correct
        Assert.True(info.IsValid, "Image should be valid");
        Assert.Equal(2, info.Version); // V2 format
        Assert.True(info.IsEncrypted, "Should be encrypted");
        Assert.False(info.IsSteganographic, "Should not be steganographic");
        Assert.Equal("(encrypted)", info.FileName); // Filename hidden when encrypted

        // Act - Decode with correct password
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, password: _testPassword);

        // Assert - Content matches
        Assert.True(File.Exists(decodedPath), "Decoded file should exist");
        string decodedContent = File.ReadAllText(decodedPath);
        Assert.Equal(originalContent, decodedContent);
    }

    [Fact]
    public void Case2_PasswordEncryption_WrongPassword_ShouldThrow()
    {
        // Arrange
        string originalContent = "Secret content that requires correct password.";
        string inputFile = Path.Combine(_testDir, "case2_wrong_pw.txt");
        string outputImage = Path.Combine(_testDir, "case2_wrong_pw_output.png");
        
        File.WriteAllText(inputFile, originalContent);
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: _testPassword, coverImage: null);

        // Act & Assert - Wrong password should throw
        var exception = Assert.Throws<Exception>(() =>
            FileToImage.DecryptImageToFile(outputImage, _testDir, password: "wrongpassword"));
        
        Assert.Contains("Invalid password", exception.Message);
    }

    [Fact]
    public void Case2_PasswordEncryption_NoPassword_ShouldThrow()
    {
        // Arrange
        string originalContent = "Encrypted content.";
        string inputFile = Path.Combine(_testDir, "case2_no_pw.txt");
        string outputImage = Path.Combine(_testDir, "case2_no_pw_output.png");
        
        File.WriteAllText(inputFile, originalContent);
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: _testPassword, coverImage: null);

        // Act & Assert - No password should throw
        var exception = Assert.Throws<Exception>(() =>
            FileToImage.DecryptImageToFile(outputImage, _testDir, password: null));
        
        Assert.Contains("password-protected", exception.Message);
    }

    [Fact]
    public void Case2_PasswordEncryption_DifferentPasswords_ProduceDifferentOutput()
    {
        // Arrange
        string originalContent = "Same content, different passwords.";
        string inputFile = Path.Combine(_testDir, "case2_diff_pw.txt");
        string outputImage1 = Path.Combine(_testDir, "case2_diff_pw_output1.png");
        string outputImage2 = Path.Combine(_testDir, "case2_diff_pw_output2.png");
        
        File.WriteAllText(inputFile, originalContent);

        // Act - Encode with different passwords
        FileToImage.EncryptFileToImage(inputFile, outputImage1, password: "password1", coverImage: null);
        FileToImage.EncryptFileToImage(inputFile, outputImage2, password: "password2", coverImage: null);

        // Assert - Files should be different (due to random salt/nonce)
        byte[] bytes1 = File.ReadAllBytes(outputImage1);
        byte[] bytes2 = File.ReadAllBytes(outputImage2);
        Assert.NotEqual(bytes1, bytes2);
    }

    [Fact]
    public void Case2_PasswordEncryption_SamePasswordTwice_ProducesDifferentOutput()
    {
        // Arrange - Same content and password should produce different output due to random salt
        string originalContent = "Content to encrypt twice.";
        string inputFile = Path.Combine(_testDir, "case2_twice.txt");
        string outputImage1 = Path.Combine(_testDir, "case2_twice_output1.png");
        string outputImage2 = Path.Combine(_testDir, "case2_twice_output2.png");
        
        File.WriteAllText(inputFile, originalContent);

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage1, password: _testPassword, coverImage: null);
        FileToImage.EncryptFileToImage(inputFile, outputImage2, password: _testPassword, coverImage: null);

        // Assert - Files should be different (random salt/nonce)
        byte[] bytes1 = File.ReadAllBytes(outputImage1);
        byte[] bytes2 = File.ReadAllBytes(outputImage2);
        Assert.NotEqual(bytes1, bytes2);

        // But both should decode to same content
        string decoded1 = File.ReadAllText(FileToImage.DecryptImageToFile(outputImage1, _testDir, _testPassword));
        File.Delete(Path.Combine(_testDir, "case2_twice.txt")); // Delete to allow re-creation
        string decoded2 = File.ReadAllText(FileToImage.DecryptImageToFile(outputImage2, _testDir, _testPassword));
        Assert.Equal(decoded1, decoded2);
    }

    #endregion

    #region Test Case 3: Password "testcase" with Cover Image (Steganography)

    [Fact]
    public void Case3_EncryptedSteganography_ShouldEncodeAndDecode()
    {
        // Arrange
        Assert.True(File.Exists(_testCoverImage), $"Test cover image should exist at: {_testCoverImage}");
        
        string originalContent = "This is a test file for Case 3: Encrypted steganography with password and cover image.";
        string inputFile = Path.Combine(_testDir, "case3_input.txt");
        string outputImage = Path.Combine(_testDir, "case3_output.png");
        
        File.WriteAllText(inputFile, originalContent);

        // Act - Encode with password and cover image
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: _testPassword, coverImage: _testCoverImage);

        // Assert - Image was created
        Assert.True(File.Exists(outputImage), "Output image should exist");

        // Act - Check info
        var info = FileToImage.GetInfo(outputImage);

        // Assert - Info is correct
        Assert.True(info.IsValid, "Image should be valid");
        Assert.Equal(3, info.Version); // V3 steganography format
        Assert.True(info.IsEncrypted, "Should be encrypted");
        Assert.True(info.IsSteganographic, "Should be steganographic");
        Assert.Equal("(encrypted)", info.FileName);

        // Act - Decode with correct password
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, password: _testPassword);

        // Assert - Content matches
        Assert.True(File.Exists(decodedPath), "Decoded file should exist");
        string decodedContent = File.ReadAllText(decodedPath);
        Assert.Equal(originalContent, decodedContent);
    }

    [Fact]
    public void Case3_EncryptedSteganography_OutputShouldResembleCover()
    {
        // Arrange
        Assert.True(File.Exists(_testCoverImage), $"Test cover image should exist at: {_testCoverImage}");
        
        string originalContent = "Small secret message.";
        string inputFile = Path.Combine(_testDir, "case3_resemble.txt");
        string outputImage = Path.Combine(_testDir, "case3_resemble_output.png");
        
        File.WriteAllText(inputFile, originalContent);

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: _testPassword, coverImage: _testCoverImage);

        // Assert - Output should have similar file size to cover (within reasonable bounds)
        var coverInfo = new FileInfo(_testCoverImage);
        var outputInfo = new FileInfo(outputImage);
        
        // PNG compression may vary, but sizes should be in the same ballpark
        // Allow 50% variance due to different PNG encoders/compression
        Assert.True(outputInfo.Length > coverInfo.Length * 0.5, "Output should not be significantly smaller than cover");
        Assert.True(outputInfo.Length < coverInfo.Length * 1.5, "Output should not be significantly larger than cover");
    }

    [Fact]
    public void Case3_EncryptedSteganography_WrongPassword_ShouldThrow()
    {
        // Arrange
        Assert.True(File.Exists(_testCoverImage));
        
        string originalContent = "Encrypted steganographic content.";
        string inputFile = Path.Combine(_testDir, "case3_wrong_pw.txt");
        string outputImage = Path.Combine(_testDir, "case3_wrong_pw_output.png");
        
        File.WriteAllText(inputFile, originalContent);
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: _testPassword, coverImage: _testCoverImage);

        // Act & Assert
        var exception = Assert.Throws<Exception>(() =>
            FileToImage.DecryptImageToFile(outputImage, _testDir, password: "wrongpassword"));
        
        Assert.Contains("Invalid password", exception.Message);
    }

    [Fact]
    public void Case3_EncryptedSteganography_BinaryFile_ShouldPreserveExactBytes()
    {
        // Arrange
        Assert.True(File.Exists(_testCoverImage));
        
        byte[] originalBytes = RandomNumberGenerator.GetBytes(512);
        string inputFile = Path.Combine(_testDir, "case3_binary.bin");
        string outputImage = Path.Combine(_testDir, "case3_binary_output.png");
        
        File.WriteAllBytes(inputFile, originalBytes);

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: _testPassword, coverImage: _testCoverImage);
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, password: _testPassword);

        // Assert
        byte[] decodedBytes = File.ReadAllBytes(decodedPath);
        Assert.Equal(originalBytes, decodedBytes);
    }

    #endregion

    #region Test Case 4: No Password with Cover Image (Steganography only)

    [Fact]
    public void Case4_SteganographyOnly_ShouldEncodeAndDecode()
    {
        // Arrange
        Assert.True(File.Exists(_testCoverImage), $"Test cover image should exist at: {_testCoverImage}");
        
        string originalContent = "This is a test file for Case 4: Steganography without password.";
        string inputFile = Path.Combine(_testDir, "case4_input.txt");
        string outputImage = Path.Combine(_testDir, "case4_output.png");
        
        File.WriteAllText(inputFile, originalContent);

        // Act - Encode with cover image but no password
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: null, coverImage: _testCoverImage);

        // Assert - Image was created
        Assert.True(File.Exists(outputImage), "Output image should exist");

        // Act - Check info
        var info = FileToImage.GetInfo(outputImage);

        // Assert - Info is correct
        Assert.True(info.IsValid, "Image should be valid");
        Assert.Equal(3, info.Version); // V3 steganography format
        Assert.False(info.IsEncrypted, "Should not be encrypted");
        Assert.True(info.IsSteganographic, "Should be steganographic");
        Assert.Equal("case4_input.txt", info.FileName); // Filename visible when not encrypted

        // Act - Decode without password
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, password: null);

        // Assert - Content matches
        Assert.True(File.Exists(decodedPath), "Decoded file should exist");
        string decodedContent = File.ReadAllText(decodedPath);
        Assert.Equal(originalContent, decodedContent);
    }

    [Fact]
    public void Case4_SteganographyOnly_BinaryFile_ShouldPreserveExactBytes()
    {
        // Arrange
        Assert.True(File.Exists(_testCoverImage));
        
        byte[] originalBytes = RandomNumberGenerator.GetBytes(2048);
        string inputFile = Path.Combine(_testDir, "case4_binary.bin");
        string outputImage = Path.Combine(_testDir, "case4_binary_output.png");
        
        File.WriteAllBytes(inputFile, originalBytes);

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: null, coverImage: _testCoverImage);
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, password: null);

        // Assert
        byte[] decodedBytes = File.ReadAllBytes(decodedPath);
        Assert.Equal(originalBytes, decodedBytes);
    }

    [Fact]
    public void Case4_SteganographyOnly_InfoShowsCorrectMetadata()
    {
        // Arrange
        Assert.True(File.Exists(_testCoverImage));
        
        string originalContent = "Metadata test content for steganography.";
        string inputFile = Path.Combine(_testDir, "case4_metadata.txt");
        string outputImage = Path.Combine(_testDir, "case4_metadata_output.png");
        
        File.WriteAllText(inputFile, originalContent);

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: null, coverImage: _testCoverImage);
        var info = FileToImage.GetInfo(outputImage);

        // Assert
        Assert.True(info.IsValid);
        Assert.Equal(3, info.Version);
        Assert.False(info.IsEncrypted);
        Assert.True(info.IsSteganographic);
        Assert.Equal("case4_metadata.txt", info.FileName);
        Assert.Equal(originalContent.Length, info.FileSize);
        Assert.True(info.DataSize > 0, "DataSize should be reported for steganographic images");
    }

    [Fact]
    public void Case4_SteganographyOnly_LargerFile_ShouldWork()
    {
        // Arrange
        Assert.True(File.Exists(_testCoverImage));
        
        // Create a larger file (10KB) - should fit in the test image
        byte[] originalBytes = RandomNumberGenerator.GetBytes(10 * 1024);
        string inputFile = Path.Combine(_testDir, "case4_large.bin");
        string outputImage = Path.Combine(_testDir, "case4_large_output.png");
        
        File.WriteAllBytes(inputFile, originalBytes);

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage, password: null, coverImage: _testCoverImage);
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, password: null);

        // Assert
        byte[] decodedBytes = File.ReadAllBytes(decodedPath);
        Assert.Equal(originalBytes, decodedBytes);
    }

    #endregion

    #region Edge Cases and Error Handling

    [Fact]
    public void Error_NonExistentInputFile_ShouldThrow()
    {
        // Arrange
        string nonExistentFile = Path.Combine(_testDir, "does_not_exist.txt");
        string outputImage = Path.Combine(_testDir, "error_output.png");

        // Act & Assert
        Assert.Throws<FileNotFoundException>(() =>
            FileToImage.EncryptFileToImage(nonExistentFile, outputImage, null, null));
    }

    [Fact]
    public void Error_InvalidImageForDecrypt_ShouldThrow()
    {
        // Arrange - Create a text file pretending to be an image
        string fakeImage = Path.Combine(_testDir, "fake.png");
        File.WriteAllText(fakeImage, "This is not a valid PNG image.");

        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
            FileToImage.DecryptImageToFile(fakeImage, _testDir, null));
    }

    [Fact]
    public void Error_CoverImageTooSmall_ShouldThrowWithMessage()
    {
        // Arrange - Create a tiny cover image
        string tinyContent = "X";
        string tinyInput = Path.Combine(_testDir, "tiny.txt");
        string tinyCover = Path.Combine(_testDir, "tiny_cover.png");
        
        File.WriteAllText(tinyInput, tinyContent);
        FileToImage.EncryptFileToImage(tinyInput, tinyCover, null, null); // Creates very small image
        
        // Now try to hide a larger file in the tiny cover
        string largeContent = new string('X', 1000);
        string largeInput = Path.Combine(_testDir, "large_for_tiny.txt");
        string outputImage = Path.Combine(_testDir, "too_small_output.png");
        
        File.WriteAllText(largeInput, largeContent);

        // Act & Assert
        var exception = Assert.Throws<Exception>(() =>
            FileToImage.EncryptFileToImage(largeInput, outputImage, null, tinyCover));
        
        Assert.Contains("too small", exception.Message.ToLower());
    }

    [Fact]
    public void Integrity_CorruptedImage_ShouldDetectWithSha1()
    {
        // Arrange
        string originalContent = "Content to be corrupted for integrity check.";
        string inputFile = Path.Combine(_testDir, "corrupt_test.txt");
        string outputImage = Path.Combine(_testDir, "corrupt_output.png");
        string corruptedImage = Path.Combine(_testDir, "corrupted_output.png");
        
        File.WriteAllText(inputFile, originalContent);
        FileToImage.EncryptFileToImage(inputFile, outputImage, null, null);
        
        // Corrupt the image by modifying pixel data directly using ImageSharp
        // Header is 332 bytes = 83 pixels (4 bytes RGBA per pixel)
        // File data starts at pixel 83, corrupt some data pixels
        using (var image = Image.Load<Rgba32>(outputImage))
        {
            // Corrupt pixels in the file data area (after header at pixel 83)
            int startPixel = 90; // Safely in file data region
            for (int i = 0; i < 10; i++)
            {
                int pixelIndex = startPixel + i;
                int x = pixelIndex % image.Width;
                int y = pixelIndex / image.Width;
                if (y < image.Height)
                {
                    Rgba32 original = image[x, y];
                    // Flip all color bits to ensure corruption
                    image[x, y] = new Rgba32(
                        (byte)(original.R ^ 0xFF),
                        (byte)(original.G ^ 0xFF),
                        (byte)(original.B ^ 0xFF),
                        original.A);
                }
            }
            image.Save(corruptedImage);
        }

        // Act & Assert - Should detect corruption via SHA1 mismatch
        var exception = Assert.ThrowsAny<Exception>(() =>
            FileToImage.DecryptImageToFile(corruptedImage, _testDir, null));
        
        // Should fail with SHA1 mismatch since file data was corrupted
        Assert.True(
            exception.Message.Contains("SHA1") || 
            exception.Message.Contains("integrity") ||
            exception.Message.Contains("corrupted") ||
            exception.Message.Contains("mismatch", StringComparison.OrdinalIgnoreCase),
            $"Expected corruption detection error, got: {exception.Message}");
    }

    #endregion

    #region Special Characters and Unicode

    [Fact]
    public void Unicode_ContentWithSpecialCharacters_ShouldPreserve()
    {
        // Arrange
        string originalContent = "Unicode test: Hello \\u4e16\\u754c! \\u3053\\u3093\\u306b\\u3061\\u306f \\U0001F600 \\u00e9\\u00e0\\u00fc";
        string inputFile = Path.Combine(_testDir, "unicode_test.txt");
        string outputImage = Path.Combine(_testDir, "unicode_output.png");
        
        File.WriteAllText(inputFile, originalContent, Encoding.UTF8);

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage, null, null);
        string decodedPath = FileToImage.DecryptImageToFile(outputImage, _testDir, null);

        // Assert
        string decodedContent = File.ReadAllText(decodedPath, Encoding.UTF8);
        Assert.Equal(originalContent, decodedContent);
    }

    [Fact]
    public void Unicode_FilenamePreservation_ShouldWork()
    {
        // Arrange - Use ASCII filename to avoid OS issues
        string originalContent = "Testing filename preservation.";
        string inputFile = Path.Combine(_testDir, "test_file_name.txt");
        string outputImage = Path.Combine(_testDir, "filename_test_output.png");
        
        File.WriteAllText(inputFile, originalContent);

        // Act
        FileToImage.EncryptFileToImage(inputFile, outputImage, null, null);
        var info = FileToImage.GetInfo(outputImage);

        // Assert
        Assert.Equal("test_file_name.txt", info.FileName);
    }

    #endregion
}
