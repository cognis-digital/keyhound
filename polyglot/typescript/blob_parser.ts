import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

const MAGIC_BYTES: Record<string, string> = {
  PE32:     '\\x4d\\x50',      // MZ
  PE64:     '\\x4d\\x50',      // MZ (same)
  ELF32:    '\\x7f\\x45\\x4c\\x46', // \x7fELF
  ELF64:    '\\x7f\\x45\\x4c\\x46', // \x7fELF (same)
  MachO32:  '\\xfeed\\xface',   // !<arch>
  MachO64:  '\\xce\\xfa\\xed\\xfe', // <arch>!
  FAT:      '\\x00\\x00\\x00\\x00', // FAT header
};

const DEFAULT_STRING_SIZE_LIMIT = 256;
const MIN_STRING_LENGTH = 8;

// ============================================================================
// TYPES
// ============================================================================

export interface DetectedFormat {
  type: string;
  arch?: string;
  entryPoint?: number;
}

export interface ExtractedString {
  offset: number;
  length: number;
  value: string;
}

export interface SecretMatch {
  pattern: string;
  offset: number;
  length: number;
  context: string;
  metadata?: Record<string, unknown>;
}

export interface BlobAnalysisResult {
  format: DetectedFormat | null;
  strings: ExtractedString[];
  secrets: SecretMatch[];
  size: number;
  offset: number;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function readUInt16LE(buffer: Buffer, offset: number): number {
  return buffer.readUInt16LE(offset);
}

function readUInt32LE(buffer: Buffer, offset: number): number {
  return buffer.readUInt32LE(offset);
}

function readStringFromBuffer(
  buffer: Buffer,
  offset: number,
  maxSize: number = DEFAULT_STRING_SIZE_LIMIT
): string | null {
  for (let i = 0; i < maxSize && i < buffer.length - offset; i++) {
    if (buffer[offset + i] === 0) {
      return buffer.slice(offset, offset + i).toString('utf8').trim();
    }
  }
  // No null terminator found within limit
  const truncated = buffer.slice(offset, offset + maxSize);
  return truncated.length > 0 
    ? truncated.toString('utf8').trim() 
    : null;
}

function readStringFromBufferRaw(
  buffer: Buffer,
  offset: number,
  maxSize: number = DEFAULT_STRING_SIZE_LIMIT
): string | null {
  for (let i = 0; i < maxSize && i < buffer.length - offset; i++) {
    if (buffer[offset + i] === 0) {
      return buffer.slice(offset, offset + i).toString('utf8');
    }
  }
  const truncated = buffer.slice(offset, offset + maxSize);
  return truncated.length > 0 
    ? truncated.toString('utf8') 
    : null;
}

function readStringFromBufferASCII(
  buffer: Buffer,
  offset: number,
  maxSize: number = DEFAULT_STRING_SIZE_LIMIT
): string | null {
  for (let i = 0; i < maxSize && i < buffer.length - offset; i++) {
    const charCode = buffer[offset + i];
    if (charCode === 0 || (charCode >= 32 && charCode <= 126)) {
      continue;
    }
    return buffer.slice(offset, offset + i).toString('ascii');
  }
  const truncated = buffer.slice(offset, offset + maxSize);
  return truncated.length > 0 
    ? truncated.toString('ascii') 
    : null;
}

function readStringFromBufferUTF16LE(
  buffer: Buffer,
  offset: number,
  maxSize: number = DEFAULT_STRING_SIZE_LIMIT
): string | null {
  let i = 0;
  while (i < maxSize && i + 1 < buffer.length - offset) {
    const low = buffer[offset + i];
    const high = buffer[offset + i + 1];
    
    if (low === 0 || high === 0) {
      // Found null terminator in UTF-16LE
      return buffer.slice(offset, offset + i * 2).toString('utf16le');
    }
    
    const charCode = low | (high << 8);
    if ((charCode >= 32 && charCode <= 126) || 
        (charCode >= 128 && charCode < 256)) {
      i += 2;
    } else {
      // Non-printable, return what we have
      return buffer.slice(offset, offset + i * 2).toString('utf16le');
    }
  }
  
  const truncated = buffer.slice(offset, offset + maxSize * 2);
  return truncated.length > 0 
    ? truncated.toString('utf16le') 
    : null;
}

function readStringFromBufferUTF16BE(
  buffer: Buffer,
  offset: number,
  maxSize: number = DEFAULT_STRING_SIZE_LIMIT
): string | null {
  let i = 0;
  while (i < maxSize && i + 1 < buffer.length - offset) {
    const high = buffer[offset + i];
    const low = buffer[offset + i + 1];
    
    if (high === 0 || low === 0) {
      return buffer.slice(offset, offset + i * 2).toString('utf16be');
    }
    
    const charCode = high | (low << 8);
    if ((charCode >= 32 && charCode <= 126) || 
        (charCode >= 128 && charCode < 256)) {
      i += 2;
    } else {
      return buffer.slice(offset, offset + i * 2).toString('utf16be');
    }
  }
  
  const truncated = buffer.slice(offset, offset + maxSize * 2);
  return truncated.length > 0 
    ? truncated.toString('utf16be') 
    : null;
}

function readStringFromBufferUTF32LE(
  buffer: Buffer,
  offset: number,
  maxSize: number = DEFAULT_STRING_SIZE_LIMIT
): string | null {
  let i = 0;
  while (i < maxSize && i + 3 < buffer.length - offset) {
    const low = buffer[offset + i];
    const mid = buffer[offset + i + 1];
    const high = buffer[offset + i + 2];
    
    if (low === 0 || mid === 0 || high === 0) {
      return buffer.slice(offset, offset + i * 4).toString('utf32le');
    }
    
    const charCode = low | (mid << 8) | (high << 16);
    if ((charCode >= 32 && charCode <= 126) || 
        (charCode >= 128 && charCode < 256)) {
      i += 4;
    } else {
      return buffer.slice(offset, offset + i * 4).toString('utf32le');
    }
  }
  
  const truncated = buffer.slice(offset, offset + maxSize * 4);
  return truncated.length > 0 
    ? truncated.toString('utf32le') 
    : null;
}

function readStringFromBufferUTF32BE(
  buffer: Buffer,
  offset: number,
  maxSize: number = DEFAULT_STRING_SIZE_LIMIT
): string | null {
  let i = 0;
  while (i < maxSize && i + 3 < buffer.length - offset) {
    const high = buffer[offset + i];
    const mid = buffer[offset + i + 1];
    const low = buffer[offset + i + 2];
    
    if (high === 0 || mid === 0 || low === 0) {
      return buffer.slice(offset, offset + i * 4).toString('utf32be');
    }
    
    const charCode = high | (mid << 8) | (low << 16);
    if ((charCode >= 32 && charCode <= 126) || 
        (charCode >= 128 && charCode < 256)) {
      i += 4;
    } else {
      return buffer.slice(offset, offset + i * 4).toString('utf32be');
    }
  }
  
  const truncated = buffer.slice(offset, offset + maxSize * 4);
  return truncated.length > 0 
    ? truncated.toString('utf32be') 
    : null;
}

// ============================================================================
// FORMAT DETECTION
// ============================================================================

function detectFormat(buffer: Buffer): DetectedFormat | null {
  if (buffer.length < 6) {
    return null;
  }

  // Check for FAT header
  const fatHeader = buffer.slice(0, 4).toString('binary');
  if (fatHeader === '   ') {
    return { type: 'FAT', arch: undefined };
  }

  // Check for Mach-O headers
  const machO32Header = buffer.slice(0, 4).toString('hex');
  if (machO32Header.startsWith('feedface')) {
    return { type: 'Mach-O', arch: 'i386' };
  }

  const machO64Header = buffer.slice(0, 4).toString('hex');
  if (machO64Header.startsWith('cefacedfe')) {
    return { type: 'Mach-O', arch: 'x86_64' };
  }

  // Check for ELF headers
  const elfHeader = buffer.slice(0, 4).toString('hex');
  if (elfHeader === '7f454c46') {
    // Check for 32-bit vs 64-bit ELF
    if (buffer.length >= 18) {
      const e_machine = readUInt16LE(buffer, 0x12);
      if (e_machine === 0x03 || e_machine === 0x05) { // ARM or ARM64
        return { type: 'ELF', arch: e_machine === 0x03 ? 'ARM' : 'ARM64' };
      } else if (e_machine === 0x02) { // SPARC
        return { type: 'ELF', arch: 'SPARC' };
      } else if (e_machine === 0x01 || e_machine === 0x03) { // S390 or S390X
        return { type: 'ELF', arch: e_machine === 0x01 ? 'S390' : 'S390X' };
      } else if (e_machine === 0x28 || e_machine === 0x34) { // IA-64 or x86_64
        return { type: 'ELF', arch: e_machine === 0x28 ? 'IA-64' : 'x86_64' };
      } else if (e_machine === 0x3e) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x2a) { // ARM64
        return { type: 'ELF', arch: 'ARM64' };
      } else if (e_machine === 0x2b) { // AArch64
        return { type: 'ELF', arch: 'AArch64' };
      } else if (e_machine === 0x37) { // RISC-V 64-bit
        return { type: 'ELF', arch: 'RISC-V-64' };
      } else if (e_machine === 0x50 || e_machine === 0x51) { // PowerPC or PowerPC64
        return { type: 'ELF', arch: e_machine === 0x50 ? 'PowerPC' : 'PowerPC64' };
      } else if (e_machine === 0x2c || e_machine === 0x38) { // MIPS or MIPS64
        return { type: 'ELF', arch: e_machine === 0x2c ? 'MIPS' : 'MIPS64' };
      } else if (e_machine === 0x3f) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x2d) { // Alpha
        return { type: 'ELF', arch: 'Alpha' };
      } else if (e_machine === 0x35) { // IA-64
        return { type: 'ELF', arch: 'IA-64' };
      } else if (e_machine === 0x2f) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x39) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x2e) { // IA-64
        return { type: 'ELF', arch: 'IA-64' };
      } else if (e_machine === 0x3a) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x3b) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x3c) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x3d) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x3e) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x3f) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x40) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x41) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x42) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x43) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x44) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x45) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x46) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x47) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x48) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x49) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x4a) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x4b) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x4c) { // x86_64
        return { type: 'ELF', arch: 'x86_64' };
      } else if (e_machine === 0x4d) { // x86_6