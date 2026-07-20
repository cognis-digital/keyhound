# frozen_string_literal: true

require 'digest/sha256'
require 'openssl'
require 'zlib'
require 'stringio'

module Polyglot
  module Ruby
    # = Blob Parser for KeyHunt
    #
    # Scans firmware blobs and filesystem dumps for hardcoded private keys,
    # API tokens, default creds, and weak RSA/ECC material.
    #
    # Usage:
    #   require_relative 'blob_parser'
    #   parser = Polyglot::Ruby::BlobParser.new('firmware.bin')
    #   results = parser.scan!
    #   p(results)

    class BlobParser
      VERSION = '1.0.0'

      # ==================== CONFIGURATION ====================

      DEFAULT_CREDENTIALS = {
        :admin => ['admin', 'root', 'administrator', 'guest', 'user'],
        :password => ['password', '123456', 'qwerty', 'letmein', 'admin', 'master', 'passw0rd'],
        :ssh_key => [
          '-----BEGIN RSA PRIVATE KEY-----',
          '-----BEGIN EC PRIVATE KEY-----',
          '-----BEGIN OPENSSH PRIVATE KEY-----',
          '-----BEGIN DSA PRIVATE KEY-----'
        ]
      }

      TOKEN_PATTERNS = {
        :api_key => [
          /(?i)api[_-]?key\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{16,64})['"]?/m,
          /(?i)["']api[_-]?secret["']\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{32,128})['"]?/m,
          /Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/,
          /Authorization:\s*Bearer\s+([A-Za-z0-9_\-]{32,128})/,
        ],
        :jwt_secret => [
          /(?i)jwt[_-]?secret\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{16,64})['"]?/m,
          /(?i)["']secret_key["']\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{32,128})['"]?/m,
        ],
        :aws => [
          /(?i)aws[_-]?access[_-]?key\s*[:=]\s*['"]?([A-Z0-9]{20})['"]?/m,
          /(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"]?([a-zA-Z0-9\/+=]{40})['"]?/m,
        ],
        :google => [
          /(?i)google[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{25,60})['"]?/m,
          /(?i)["']GOOGLE_APPLICATION_CREDENTIALS["']\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{32,128})['"]?/m,
        ],
        :github => [
          /(?i)github[_-]?token\s*[:=]\s*['"]?ghp_[A-Za-z0-9_\-]{36}['"]?/m,
          /(?i)["']personal_access_token["']\s*[:=]\s*['"]?(ghp_|gho_|ghu_)?[A-Za-z0-9_\-]{36}['"]?/m,
        ],
        :slack => [
          /(?i)slack[_-]?token\s*[:=]\s*['"]?xapp-[A-Za-z0-9_\-]{59}['"]?/m,
          /(?i)["']bot_token["']\s*[:=]\s*['"]?(xoxb|xapp)-[A-Za-z0-9_\-]{59}['"]?/m,
        ],
        :slack_webhook => [
          /(?i)webhook_url\s*[:=]\s*https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\-]+/,
        ],
      }

      WEAK_RSA_MODULI = {
        512 => 'RSA-512 (weak)',
        768 => 'RSA-768 (weak)',
        1024 => 'RSA-1024 (weak)',
        1536 => 'RSA-1536 (weak)',
      }

      WEAK_ECC_CURVES = {
        :secp112r1 => 'SECP112R1',
        :secp128r1 => 'SECP128R1',
        :secp160k1 => 'SECP160K1 (weak)',
        :secp160r1 => 'SECP160R1',
        :secp192r1 => 'SECP192R1',
        :prime192v1 => 'PRIME192V1',
        :secp224r1 => 'SECP224R1',
        :secp256k1 => 'SECP256K1 (common, verify order)',
        :secp384r1 => 'SECP384R1',
        :prime384v1 => 'PRIME384V1',
        :secp521r1 => 'SECP521R1',
      }

      # ==================== BLOB DETECTION ====================

      class << self
        def detect_format(data)
          return :raw unless data.is_a?(String) || data.respond_to?(:bytesize)

          size = data.bytesize rescue 0
          return :raw if size < 4

          header = data[0, 4] || ''
          magic = header.unpack1('C*')

          case magic
          when 0x4D5A # "MZ"
            return :pe32
          when 0x7F454C46 # "\x7FELF"
            return :elf
          when 0x0100, 0x0200, 0x0300 # FAT32 signatures
            return :fat32
          when 0x58454C46 # "XELF" (little-endian ELF)
            return :elf_le
          else
            return :raw
          end
        end

        def detect_compression(data)
          return :none unless data.is_a?(String) || data.respond_to?(:bytesize)

          size = data.bytesize rescue 0
          return :none if size < 4

          header = data[0, 2] || ''
          magic = header.unpack1('C*')

          case magic
          when 0x78 # "x" (deflate)
            return :gzip
          when 0x504B0304 # PKZIP signature
            return :zip
          when 0x504B0506, 0x504B0707 # Zip64 signatures
            return :zip64
          else
            return :none
          end
        end

        def decompress_gzip(data)
          begin
            Zlib::GzipReader.new(StringIO.new(data)).read
          rescue Zlib::Error, StandardError
            data
          end
        end

        def decompress_zip(data)
          begin
            Zlib::Inflate.inflate(data)
          rescue Zlib::Error, StandardError
            data
          end
        end
      end

      # ==================== CONSTRUCTOR ====================

      attr_reader :filename, :format, :compressed, :raw_data, :file_size

      def initialize(path_or_data = nil, options = {})
        @filename = path_or_data.is_a?(String) ? path_or_data : 'blob'
        @options = {
          max_depth: 1024 * 1024, # 1MB default for recursion depth
          chunk_size: 65536,       # 64KB chunks for streaming
          include_metadata: true,
          detect_compression: true,
        }.merge(options)

        @format = nil
        @compressed = false
        @raw_data = nil
        @file_size = 0

        if path_or_data.is_a?(String) && File.exist?(path_or_data)
          load_from_file(path_or_data)
        else
          @raw_data = path_or_data || ''
          detect_format(@raw_data)
        end
      end

      def load_from_file(path)
        begin
          @file_size = File.size(path)
          if @file_size > 10 * 1024 * 1024 # 10MB limit for memory loading
            raise "File too large: #{@file_size} bytes"
          end

          @raw_data = File.binread(path)
          detect_format(@raw_data)
        rescue StandardError => e
          @format = :error
          @raw_data = path.to_s
          $stderr.puts "[BlobParser] Error loading #{path}: #{e.message}"
        end
      end

      # ==================== PARSING ====================

      def parse!
        results = []

        case @format
        when :pe32, :elf, :elf_le, :raw, :fat32
          results << extract_strings_from_binary(@raw_data)
        else
          results << { type: :unknown, data: @raw_data.to_s[0..512] }
        end

        # Try to decompress if compressed
        if @compressed && @format == :gzip
          begin
            decompressed = self.class.decompress_gzip(@raw_data)
            results << { type: :decompressed, data: decompressed.to_s[0..512] }
          rescue StandardError
            # Fall back to original
          end
        end

        @results = results
        results
      end

      def extract_strings_from_binary(data)
        strings = []
        chunk_size = 64 * 1024

        data.each_chunk(chunk_size) do |chunk|
          # Extract printable ASCII sequences (length >= 8, max 256)
          matches = chunk.scan(/[\x20-\x7E]{8,256}/m).flatten
          strings.concat(matches.map { |s| s.encode('ASCII-8BIT') })
        end

        # Deduplicate and limit
        unique_strings = strings.uniq.take(10_000)
        [{ type: :strings, data: unique_strings.join(' ') }]
      end

      def extract_metadata_headers(data)
        headers = []

        case @format
        when :pe32
          begin
            pe_offset = data[0, 4].unpack1('V') == 0x4D5A ? 64 : 0
            if pe_offset > 0 && data.bytesize > pe_offset + 256
              headers << { type: :PE_HEADER, offset: pe_offset }
              # Extract PE header info
              pe_header = data[pe_offset, 256]
              headers << { type: :PE_INFO, info: pe_header.to_s[0..128] }
            end
          rescue StandardError
            headers << { type: :PE_ERROR, error: $!.message }
          end

        when :elf
          begin
            endian = data[0, 4].unpack1('V') == 0x7F454C46 ? 'LE' : 'BE'
            elf_header_offset = 0x3C # Standard ELF header offset
            if elf_header_offset < data.bytesize
              headers << { type: :ELF_HEADER, endian: endian }
              # Extract program headers and section headers offsets
              phoff = data[elf_header_offset + 0x28, 4].unpack1('V') & 0xFFFF_FFFF
              shoff = data[elf_header_offset + 0x30, 4].unpack1('V') & 0xFFFF_FFFF
                headers << { type: :ELF_OFFSETS, phoff: phoff, shoff: shoff } if phoff > 0 || shoff > 0
            end
          rescue StandardError
            headers << { type: :ELF_ERROR, error: $!.message }
          end

        when :fat32
          begin
            fat_offset = data[0, 4].unpack1('V') == 0x58454C46 ? 28 : 0
            if fat_offset > 0 && data.bytesize > fat_offset + 128
              headers << { type: :FAT32_HEADER, offset: fat_offset }
              # Extract boot sector info
              boot_sector = data[fat_offset, 512]
              headers << { type: :FAT32_INFO, info: boot_sector.to_s[0..256] }
            end
          rescue StandardError
            headers << { type: :FAT_ERROR, error: $!.message }
          end

        else
          headers << { type: :UNKNOWN_FORMAT, format: @format }
        end

        headers
      end

      # ==================== SECRET DETECTION ====================

      def detect_secrets!
        results = []

        # 1. Extract all printable strings first
        string_results = extract_strings_from_binary(@raw_data)
        string_data = string_results.first[:data] rescue ''

        # 2. Check for default credentials
        cred_results = check_credentials(string_data, @raw_data)

        # 3. Check for API tokens and secrets
        token_results = check_tokens(string_data, @raw_data)

        # 4. Check for weak cryptographic material
        crypto_results = check_crypto_material(@raw_data)

        # 5. Check for hardcoded passwords in common formats
        password_results = check_password_formats(string_data)

        results.concat([string_results, cred_results, token_results, crypto_results, password_results].flatten.compact)
      end

      def check_credentials(strings, binary)
        creds = []

        # Check for default username/password pairs
        usernames = DEFAULT_CREDENTIALS[:admin]
        passwords = DEFAULT_CREDENTIALS[:password]

        usernames.each do |user|
          passwords.each do |pass|
            pattern = /#{Regexp.escape(user)}\s*[:=]\s*#{Regexp.escape(pass)}/i
            if strings.match?(pattern) || binary.match?(pattern)
              creds << { type: :default_creds, user: user, password: pass }
            end
          end
        end

        # Check for SSH keys in the data
        ssh_patterns = DEFAULT_CREDENTIALS[:ssh_key]
        ssh_patterns.each do |pattern|
          if strings.match?(pattern) || binary.match?(pattern)
            creds << { type: :ssh_key, pattern: pattern }
          end
        end

        [{ type: :credentials, data: creds }]
      end

      def check_tokens(strings, binary)
        tokens = []

        TOKEN_PATTERNS.each do |category, patterns|
          patterns.each do |pattern|
            if strings.match?(pattern) || binary.match?(pattern)
              match = strings.match(pattern) || binary.match(pattern)
              captured = match ? (match.captures.first || match[0]) : ''

              tokens << {
                type: category,
                pattern: pattern.to_s,
                value: captured,
                length: captured.bytesize,
              }
            end
          end
        end

        [{ type: :tokens, data: tokens }] if tokens.any?
      end

      def check_crypto_material(binary)
        crypto = []

        # Check for weak RSA moduli (common small primes)
        common_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31].map { |p| p ** 64 }

        common_primes.each do |prime|
          if binary.match?(/#{Regexp.escape(prime.to_s)}/)
            crypto << { type: :weak_rsa_prime, prime: prime }
          end
        end

        # Check for weak RSA moduli (known small products)
        weak_moduli = {
          0x853A4F35_16D79B2C => 'RSA-512',
          0xC3A2E2BE_7F1C4F9D => 'RSA-768',
        }

        weak_moduli.each do |modulus, name|
          if binary.match?(/#{Regexp.escape(modulus.to_s)}/)
            crypto << { type: :weak_rsa_modulus, modulus: modulus, name: name }
          end
        end

        # Check for common ECC curve parameters
        WEAK_ECC_CURVES.each do |curve_name, display_name|
          case curve_name
          when :secp160k1
            if binary.match?(/SECP160K1/i) || binary.match?(/a=0x536D_A7E_94C/ix)
              crypto << { type: :weak_ecc_curve, curve: display_name }
            end
          when :secp256k1
            if binary.match?(/SECP256K1/i) || binary.match?(/a=0x1\.\.4/ix)
              crypto << { type: :common_ecc_curve, curve: display_name