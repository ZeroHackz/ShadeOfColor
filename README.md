# ShadeOfColor

**Turn any file into an image, and back again.**  
A simple cross-platform tool to hide files inside PNG images with optional encryption and steganography.

---

## What is ShadeOfColor?

Have you ever wanted to:

- Send a file by email that the provider does not allow?  
- Store restricted file types on cloud services that only accept images?  
- Add an extra layer of privacy when sharing files publicly?  
- Are you a journalist in a totalitarian state and need to release a file?
- Exfiltrate data into systems that monitor suspicious files? 

With ShadeOfColor, you can **convert any file into an image** (`-crypt`) and later **recover the original file** (`-decrypt`).  
The output looks like a normal PNG, but it actually carries your data inside its pixels.

Process  
![screenshot-file](https://raw.githubusercontent.com/archistico/ShadeOfColor2/refs/heads/main/screenshot-process.png)

### Screenshot

FileToImage  
![screenshot-file](https://raw.githubusercontent.com/archistico/ShadeOfColor2/refs/heads/main/screenshot-file.png)

ImageToImage  
![screenshot-image](https://raw.githubusercontent.com/archistico/ShadeOfColor2/refs/heads/main/screenshot-image.png)

---

## Features

- **Two-way conversion**:  
  - `-crypt`: transform a file into a PNG image.  
  - `-decrypt`: restore the original file from the PNG.  

- **AES-256-GCM Encryption**:
  - Password-based encryption using PBKDF2 key derivation (100,000 iterations)
  - Authenticated encryption prevents tampering
  - Use `-password` flag to encrypt/decrypt files

- **LSB Steganography**:
  - Hide data inside existing images using Least Significant Bit encoding
  - Uses 2 bits per RGB channel for minimal visual impact
  - Use `-cover` flag to embed data in a cover image

- **Metadata Inspection**:
  - `-info`: display image metadata without extracting the file
  - Shows version, encryption status, filename, and file size

- **Embedded metadata**:  
  - Signature `"ER"`  
  - Original file size  
  - Original filename  
  - SHA1 hash for integrity check  

- **Cross-platform**: uses [SixLabors.ImageSharp](https://github.com/SixLabors/ImageSharp). Works on Windows, Linux, macOS.  

- **Integrity check**: ensures the file is not corrupted or tampered with via SHA1 verification.

- **Backward compatible**: can decode legacy v1 images from older versions.

---

## Usage

### Install
```bash
Install-package SixLabors.ImageSharp
```

### Basic: Encrypt a file into an image
```bash
# With executable (download release)
./ShadeOfColor2.exe -crypt myfile.exe output.png

# Alternative with dotnet
dotnet run -crypt FileToImage.cs out.png
```

### Basic: Decrypt an image back into the original file
```bash
./ShadeOfColor2.exe -decrypt output.png
```

### With Password Encryption
```bash
# Encrypt with password
./ShadeOfColor2.exe -crypt secret.txt output.png -password mypassword

# Decrypt with password
./ShadeOfColor2.exe -decrypt output.png -password mypassword

# Interactive password prompt (masked input)
./ShadeOfColor2.exe -crypt secret.txt output.png -password
```

### With Steganography (Hide in Existing Image)
```bash
# Hide data inside a cover image
./ShadeOfColor2.exe -crypt secret.txt output.png -cover photo.png

# Combine encryption and steganography
./ShadeOfColor2.exe -crypt secret.txt output.png -cover photo.png -password mypassword

# Decryption auto-detects steganography
./ShadeOfColor2.exe -decrypt output.png -password mypassword
```

### View Image Metadata
```bash
./ShadeOfColor2.exe -info output.png
```

Output example:
```
=== Image Info ===
Valid:          True
Version:        3
Encrypted:      True
Steganographic: True
File Name:      secret.txt
File Size:      1234 bytes
```

---

## Header Format

### Version 2/3 Header (332 bytes)
| Field      | Size    | Description                    |
|------------|---------|--------------------------------|
| Signature  | 2 bytes | "ER"                           |
| Version    | 1 byte  | 0x02 (encrypted) or 0x03 (stego) |
| Flags      | 1 byte  | 0x01=encrypted, 0x02=stego     |
| Salt       | 16 bytes| PBKDF2 salt                    |
| Nonce      | 12 bytes| AES-GCM nonce                  |
| File Size  | 8 bytes | int64                          |
| Filename   | 256 bytes| UTF-8 padded                  |
| SHA1       | 20 bytes| File integrity hash            |
| Auth Tag   | 16 bytes| AES-GCM authentication tag     |

### Legacy v1 Header (286 bytes)
| Field      | Size    | Description                    |
|------------|---------|--------------------------------|
| Signature  | 2 bytes | "ER"                           |
| File Size  | 8 bytes | int64                          |
| Filename   | 256 bytes| UTF-8 padded                  |
| SHA1       | 20 bytes| File integrity hash            |

---

## Testing

The project includes a comprehensive test suite with 23 test cases covering:

- Default encoding (no password, no cover image)
- Password encryption only
- Password + steganography combined
- Steganography only (no password)
- Edge cases and error handling
- Integrity verification

Run tests:
```bash
dotnet test
```

---

## Security Notes

- **AES-256-GCM** provides authenticated encryption (confidentiality + integrity)
- **PBKDF2** with 100,000 iterations for key derivation (OWASP recommended)
- **SHA1** hash for file integrity verification
- Steganography uses 2 bits per channel - visually imperceptible but not cryptographically secure on its own
- For maximum security, combine encryption (-password) with steganography (-cover)

---

## Disclaimer

ShadeOfColor is a tool for privacy and experimentation.
It is not intended to be used for illegal purposes. Please respect the terms of service of the platforms where you use it.

---

## Contribute

Ideas, issues, and pull requests are welcome!
Help us make ShadeOfColor even more powerful and versatile.

---

## License

MIT License - feel free to use, modify, and share.
