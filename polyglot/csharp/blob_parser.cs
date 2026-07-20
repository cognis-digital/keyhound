using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Polyglot.CSharp
{
    /// <summary>
    /// Configuration for blob scanning behavior.
    /// </summary>
    public sealed class BlobScanConfig
    {
        public const int DefaultMaxBlobSize = 1024 * 1024 * 10; // 10MB default
        
        public int MaxBlobSizeBytes { get; set; } = DefaultMaxBlobSize;
        
        /// <summary>Minimum hex string length to consider as potential key material.</summary>
        public int MinHexStringLength { get; set; } = 64;
        
        /// <summary>Minimum base64 string length to consider as potential key material.</summary>
        public int MinBase64StringLength { get; set; } = 88; // ~128 bits
        
        /// <summary>Threshold for weak RSA modulus (bits).</summary>
        public int WeakRsaModulusBits { get; set; } = 512;
        
        /// <summary>Threshold for weak ECC key size (bits).</summary>
        public int WeakEccKeyBits { get; set; } = 160;
    }

    /// <summary>
    /// Represents a discovered secret or potential credential.
    /// </summary>
    public sealed class FoundSecret
    {
        public string Type { get; set; }
        public string Category { get; set; } // e.g., "Private Key", "API Token"
        public string Value { get; set; }
        public int OffsetInBlob { get; set; }
        public long BlobOffset { get; set; } // If blob is part of larger stream
        public byte[] ContextBytes { get; set; } // Surrounding bytes for context
        
        public override string ToString() => $"{Type} [{Category}]: {Value?.Substring(0, Math.Min(Value.Length, 64))}...";
    }

    /// <summary>
    /// Represents a detected file type within the blob.
    /// </summary>
    public sealed class DetectedFileType
    {
        public string MagicName { get; set; }
        public int Offset { get; set; }
        public int Length { get; set; }
        public byte[] Signature { get; set; }
        
        public override string ToString() => $"{MagicName} at offset {Offset}, len {Length}";
    }

    /// <summary>
    /// Represents a detected cryptographic parameter.
    /// </summary>
    public sealed class DetectedCryptoParam
    {
        public string Type { get; set; } // "RSA Modulus", "ECC Curve"
        public string Name { get; set; }
        public int BitLength { get; set; }
        public byte[] ValueHex { get; set; }
        
        public bool IsWeak => 
            (Type == "RSA Modulus" && BitLength < BlobScanConfig.WeakRsaModulusBits) ||
            (Type == "ECC Key" && BitLength < BlobScanConfig.WeakEccKeyBits);
    }

    /// <summary>
    /// Main blob parser and scanner.
    /// </summary>
    public sealed class BlobParser : IDisposable
    {
        private readonly List<DetectedFileType> _fileTypes = new();
        private readonly List<FoundSecret> _secrets = new();
        private readonly List<DetectedCryptoParam> _cryptoParams = new();
        
        /// <summary>
        /// Known magic signatures for common file types.
        /// Format: (MagicName, Signature bytes).
        /// </summary>
        private static readonly (string Name, byte[] Sig)[] FileSignatures = {
            ("PE/COFF", new byte[] { 0x4D, 0x5A }),           // PE header "MZ"
            ("ELF", new byte[] { 0x7F, 0x45, 0x4C, 0x46 }),   // ELF magic
            ("Mach-O", new byte[] { 0xFE, 0xED }),            // Mach-O fat header
            ("ZIP", new byte[] { 0x50, 0x4B, 0x03, 0x04 }),   // ZIP local file header
            ("GZIP", new byte[] { 0x1F, 0x8B }),              // GZIP magic
            ("PNG", new byte[] { 0x89, 0x50, 0x4E, 0x47 }),   // PNG signature
            ("JPEG", new byte[] { 0xFF, 0xD8 }),              // JPEG start
            ("PDF", new byte[] { 0x25, 0x50, 0x44, 0x46 }),   // PDF header "%PDF"
            ("PEM/DER", new byte[] { 0x30, 0x82 }),           // DER sequence (common in certs)
        };

        public BlobScanConfig Config { get; } = new BlobScanConfig();
        
        /// <summary>Regex for common private key headers.</summary>
        private static readonly Regex PemHeaderRegex = 
            new(@"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|ENCRYPTED)\s+PRIVATE KEY-----", RegexOptions.Compiled);

        /// <summary>Regex for common PEM footers.</summary>
        private static readonly Regex PemFooterRegex = 
            new(@"-----END\s+(RSA|EC|DSA|OPENSSH|ENCRYPTED)\s+PRIVATE KEY-----", RegexOptions.Compiled);

        /// <summary>Regex for base64-encoded strings (with padding validation).</summary>
        private static readonly Regex Base64Pattern = 
            new(@".{0,12}(?:[A-Za-z0-9+/]{4})?(?:[A-Za-z0-9+/]{2}==)?(?:[A-Za-z0-9+/]{2}=)?", RegexOptions.Compiled);

        /// <summary>Regex for common token prefixes.</summary>
        private static readonly Regex TokenPrefixPattern = 
            new(@"(Bearer|Basic|API-Key|X-API-Key|Authorization):\s*([A-Za-z0-9_\-\.]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public BlobParser(BlobScanConfig config) => Config = config ?? new BlobScanConfig();

        /// <summary>
        /// Scans a byte array for secrets, file types, and crypto parameters.
        /// </summary>
        public void Scan(byte[] blob)
        {
            if (blob == null || blob.Length > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"Blob size {blob.Length} exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            // 1. Detect embedded file types
            DetectFileTypes(blob);

            // 2. Extract and analyze potential secrets
            ExtractSecrets(blob);

            // 3. Analyze crypto parameters if keys found
            AnalyzeCryptoParams(blob);

            // 4. Check for weak RSA/ECC material
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a stream (memory-mapped or large file) without loading entirely into memory.
        /// </summary>
        public void Scan(Stream blob, long totalSize = -1)
        {
            if (blob == null || totalSize > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"Stream size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            using var buffer = new Memory<byte>(blob);
            int offset = 0;
            const int chunkSize = 65536; // 64KB chunks for streaming

            while (offset < blob.Length)
            {
                int readLen = Math.Min(chunkSize, blob.Length - offset);
                Span<byte> chunkSpan = buffer.Slice(offset, readLen).Span;
                
                // Detect file types in this chunk
                foreach (var (name, sig) in FileSignatures)
                {
                    if (chunkSpan.StartsWith(sig))
                    {
                        _fileTypes.Add(new DetectedFileType 
                        { 
                            MagicName = name, 
                            Offset = offset, 
                            Length = readLen - 4, // Approximate
                            Signature = new byte[] { sig[0], sig[1] }
                        });
                    }
                }

                // Extract secrets from this chunk
                ExtractSecretsFromChunk(chunkSpan.ToArray(), offset);

                offset += readLen;
            }

            AnalyzeCryptoParams(blob);
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a file path directly.
        /// </summary>
        public void Scan(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("File path cannot be null or empty", nameof(filePath));

            using var stream = File.OpenRead(filePath);
            long size = stream.Length;
            
            // Check if file fits in memory
            if (size <= Config.MaxBlobSizeBytes)
            {
                byte[] data = new byte[size];
                stream.ReadFully(data);
                Scan(data);
            }
            else
            {
                Scan(stream, size);
            }
        }

        /// <summary>
        /// Scans multiple blobs/files at once.
        /// </summary>
        public void ScanMultiple(params string[] filePaths)
        {
            foreach (var path in filePaths)
            {
                try
                {
                    if (!File.Exists(path))
                        throw new FileNotFoundException($"Path not found: {path}", path);

                    using var stream = File.OpenRead(path);
                    long size = stream.Length;
                    
                    byte[] data;
                    if (size <= Config.MaxBlobSizeBytes)
                    {
                        data = new byte[size];
                        stream.ReadFully(data);
                        Scan(data);
                    }
                    else
                    {
                        Scan(stream, size);
                    }

                    // Append results with source info
                    _secrets.AddRange(_secrets.Select(s => 
                    {
                        var copy = s;
                        copy.Type += $"|{path}";
                        return copy;
                    }));
                }
                catch (Exception ex)
                {
                    // Log error but continue scanning others
                    Console.Error.WriteLine($"Error scanning '{path}': {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Scans a memory-mapped file.
        /// </summary>
        public void Scan(Memory<byte> blob)
        {
            if (blob.Length > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"Memory size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            ExtractSecretsFromChunk(blob.ToArray(), 0);
            AnalyzeCryptoParams(new MemoryStream(blob.ToArray()));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a span of bytes.
        /// </summary>
        public void Scan(Span<byte> blob)
        {
            if (blob.Length > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"Span size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            ExtractSecretsFromChunk(blob.ToArray(), 0);
            AnalyzeCryptoParams(new MemoryStream(blob.ToArray()));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a ReadOnlySpan of bytes.
        /// </summary>
        public void Scan(ReadOnlySpan<byte> blob)
        {
            if (blob.Length > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"Span size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            ExtractSecretsFromChunk(blob.ToArray(), 0);
            AnalyzeCryptoParams(new MemoryStream(blob.ToArray()));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a string as if it were binary data (useful for config files, scripts).
        /// </summary>
        public void Scan(string text)
        {
            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            byte[] bytes = Encoding.UTF8.GetBytes(text);
            ExtractSecretsFromChunk(bytes, 0);
            
            // Check for common config file patterns
            if (text.Contains("password") || text.Contains("secret") || 
                text.Contains("token") || text.Contains("api_key"))
            {
                _secrets.Add(new FoundSecret 
                { 
                    Type = "Potential Credential", 
                    Category = "Configuration String", 
                    Value = text.Substring(0, Math.Min(text.Length, 128)),
                    OffsetInBlob = 0
                });
            }

            AnalyzeCryptoParams(new MemoryStream(bytes));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a memory-mapped file (for very large files).
        /// </summary>
        public void Scan(MemoryMappedFile blob)
        {
            if (blob.Length > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"MMap size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            ExtractSecretsFromChunk(blob.ToArray(), 0);
            AnalyzeCryptoParams(new MemoryStream(blob.ToArray()));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a file-like object with custom length.
        /// </summary>
        public void Scan(FileLike blob)
        {
            if (blob.Length > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"FileLike size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            ExtractSecretsFromChunk(blob.ToArray(), 0);
            AnalyzeCryptoParams(new MemoryStream(blob.ToArray()));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a file-like object with custom length.
        /// </summary>
        public void Scan(FileLike blob, long totalSize)
        {
            if (totalSize > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"FileLike size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            ExtractSecretsFromChunk(blob.ToArray(), 0);
            AnalyzeCryptoParams(new MemoryStream(blob.ToArray()));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a file-like object with custom length.
        /// </summary>
        public void Scan(FileLike blob, long totalSize, int chunkSize)
        {
            if (totalSize > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"FileLike size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            ExtractSecretsFromChunk(blob.ToArray(), 0);
            AnalyzeCryptoParams(new MemoryStream(blob.ToArray()));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a file-like object with custom length.
        /// </summary>
        public void Scan(FileLike blob, long totalSize, int chunkSize, string sourceName)
        {
            if (totalSize > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"FileLike size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            ExtractSecretsFromChunk(blob.ToArray(), 0);
            AnalyzeCryptoParams(new MemoryStream(blob.ToArray()));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a file-like object with custom length.
        /// </summary>
        public void Scan(FileLike blob, long totalSize, int chunkSize, string sourceName, BlobScanConfig config)
        {
            if (totalSize > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"FileLike size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            ExtractSecretsFromChunk(blob.ToArray(), 0);
            AnalyzeCryptoParams(new MemoryStream(blob.ToArray()));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a file-like object with custom length.
        /// </summary>
        public void Scan(FileLike blob, long totalSize, int chunkSize, string sourceName, BlobScanConfig config, Action<FoundSecret> onSecret)
        {
            if (totalSize > Config.MaxBlobSizeBytes)
                throw new ArgumentException($"FileLike size exceeds max of {Config.MaxBlobSizeBytes}", nameof(blob));

            _fileTypes.Clear();
            _secrets.Clear();
            _cryptoParams.Clear();

            ExtractSecretsFromChunk(blob.ToArray(), 0);
            AnalyzeCryptoParams(new MemoryStream(blob.ToArray()));
            CheckWeakMaterial();
        }

        /// <summary>
        /// Scans a file-like object with custom length.
        /// </summary>
        public void Scan