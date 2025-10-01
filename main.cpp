// ------------------------------------------------------------------------- //
//  Self-contained SteamStub v3 unpacker By GHFear @ IllusorySoftware        //
//  Version 0.1.5                                                            //
//  Compatible with Emscripten (drop the emsdk folder next to this file and  //
//  compile with the included compile script for linux)                      //
// ------------------------------------------------------------------------- //
//  Lots of credit to Cyanic (aka Golem_x86), atom0s and illnyang for prior  //
//  research on steamstub drm.                                               //
//  Without y'all, this wouldn't be possible.                                //
// ------------------------------------------------------------------------- //

#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream> 
#include <emscripten.h>
#include <emscripten/html5.h>
#include <emscripten/val.h>

// Print AES Key hexadecimal string.
void printAESKey(const uint8_t* key, size_t size) {
    std::cout << "[*] SteamStub AES Key: 0x";
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
    }
    std::cout << std::dec << "\n";
}

// Parse IDA Signature.
static bool parse_ida_signature(const std::string& sig, std::vector<uint8_t>& pattern, std::vector<bool>& mask) {
    std::istringstream iss(sig);
    std::string token;
    while (iss >> token) {
        if (token == "?") {
            pattern.push_back(0x00);
            mask.push_back(false);
        } else if (token.size() == 2 && std::isxdigit(token[0]) && std::isxdigit(token[1])) {
            pattern.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
            mask.push_back(true);
        } else {
            return false; 
        }
    }
    return !pattern.empty();
}

// Scan binary buffer for matching IDA signature.
static size_t scan_signature(const std::vector<uint8_t>& buffer, const std::string& ida_sig) {
    std::vector<uint8_t> pattern;
    std::vector<bool> mask;
    if (!parse_ida_signature(ida_sig, pattern, mask)) return SIZE_MAX;

    size_t buf_size = buffer.size();
    size_t pat_size = pattern.size();
    if (pat_size == 0 || buf_size < pat_size) return SIZE_MAX;

    for (size_t i = 0; i <= buf_size - pat_size; ++i) {
        bool match = true;
        for (size_t j = 0; j < pat_size; ++j) {
            if (mask[j] && buffer[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return SIZE_MAX; // not found
}

static size_t pkcs7_unpad(std::vector<uint8_t>& buf) {
    if (buf.empty()) return 0;
    uint8_t pad = buf.back();
    if (pad == 0 || pad > 16 || pad > buf.size()) return buf.size();
    for (size_t i = 0; i < pad; ++i) {
        if (buf[buf.size() - 1 - i] != pad) return buf.size();
    }
    buf.resize(buf.size() - pad);
    return buf.size();
}


static const uint8_t sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t inv_sbox[256] = {
  0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
  0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
  0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
  0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
  0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
  0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
  0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
  0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
  0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
  0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
  0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
  0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
  0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
  0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
  0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
  0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
}

static uint8_t multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t temp = a;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= temp;
        uint8_t hi_bit = temp & 0x80;
        temp <<= 1;
        if (hi_bit) temp ^= 0x1B;
        b >>= 1;
    }
    return result;
}

static const uint8_t Rcon[15] = {
  0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D,0x9A
};

static void KeyExpansion256(const uint8_t key[32], uint8_t roundKeys[240]) {
    memcpy(roundKeys, key, 32);
    int bytesGenerated = 32;
    int rconIteration = 0;
    uint8_t temp[4];

    while (bytesGenerated < 240) {
        for (int i = 0; i < 4; ++i)
            temp[i] = roundKeys[bytesGenerated - 4 + i];

        if (bytesGenerated % 32 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            temp[0] ^= Rcon[rconIteration++];
        } else if (bytesGenerated % 32 == 16) {
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        for (int i = 0; i < 4; ++i) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 32] ^ temp[i];
            bytesGenerated++;
        }
    }
}

static void AddRoundKey(uint8_t state[16], const uint8_t* roundKey) {
    for (int i = 0; i < 16; ++i) state[i] ^= roundKey[i];
}

static void InvSubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) state[i] = inv_sbox[state[i]];
}

static void InvShiftRows(uint8_t state[16]) {
    uint8_t tmp[16];
    // row 0
    tmp[0] = state[0];
    tmp[4] = state[4];
    tmp[8] = state[8];
    tmp[12] = state[12];
    // row 1
    tmp[1]  = state[13];
    tmp[5]  = state[1];
    tmp[9]  = state[5];
    tmp[13] = state[9];
    // row 2
    tmp[2] = state[10];
    tmp[6] = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];
    // row 3
    tmp[3]  = state[7];
    tmp[7]  = state[11];
    tmp[11] = state[15];
    tmp[15] = state[3];
    memcpy(state, tmp, 16);
}

static void InvMixColumns(uint8_t state[16]) {
    for (int i = 0; i < 4; ++i) {
        int col = 4 * i;
        uint8_t a0 = state[col + 0];
        uint8_t a1 = state[col + 1];
        uint8_t a2 = state[col + 2];
        uint8_t a3 = state[col + 3];

        uint8_t r0 = (uint8_t)(multiply(a0, 0x0e) ^ multiply(a1, 0x0b) ^ multiply(a2, 0x0d) ^ multiply(a3, 0x09));
        uint8_t r1 = (uint8_t)(multiply(a0, 0x09) ^ multiply(a1, 0x0e) ^ multiply(a2, 0x0b) ^ multiply(a3, 0x0d));
        uint8_t r2 = (uint8_t)(multiply(a0, 0x0d) ^ multiply(a1, 0x09) ^ multiply(a2, 0x0e) ^ multiply(a3, 0x0b));
        uint8_t r3 = (uint8_t)(multiply(a0, 0x0b) ^ multiply(a1, 0x0d) ^ multiply(a2, 0x09) ^ multiply(a3, 0x0e));

        state[col + 0] = r0;
        state[col + 1] = r1;
        state[col + 2] = r2;
        state[col + 3] = r3;
    }
}

static void AES256_DecryptBlock(uint8_t state[16], const uint8_t roundKeys[240]) {
    AddRoundKey(state, roundKeys + 224);
    for (int round = 13; round >= 1; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys + 0);
}

static void AES256_ECB_decrypt(uint8_t* buf, size_t len, const uint8_t key[32]) {
    if (len % 16 != 0) return;
    uint8_t roundKeys[240];
    KeyExpansion256(key, roundKeys);
    uint8_t block[16];
    for (size_t off = 0; off < len; off += 16) {
        memcpy(block, buf + off, 16);
        AES256_DecryptBlock(block, roundKeys);
        memcpy(buf + off, block, 16);
    }
}

static void AES256_CBC_decrypt(uint8_t* buf, size_t len, const uint8_t key[32], uint8_t iv[16]) {
    if (len % 16 != 0) return;
    uint8_t roundKeys[240];
    KeyExpansion256(key, roundKeys);

    uint8_t prev[16];
    memcpy(prev, iv, 16);

    uint8_t block[16];
    for (size_t off = 0; off < len; off += 16) {
        memcpy(block, buf + off, 16);
        uint8_t cipher_block[16];
        memcpy(cipher_block, block, 16);

        AES256_DecryptBlock(block, roundKeys);
        for (int i = 0; i < 16; ++i) block[i] ^= prev[i];
        memcpy(buf + off, block, 16);
        memcpy(prev, cipher_block, 16);
    }
    memcpy(iv, prev, 16);
}

#pragma pack(push,1)
struct IMAGE_DOS_HEADER_MIN { uint16_t e_magic; uint16_t e_cblp; uint16_t e_cp; uint16_t e_crlc; uint16_t e_cparhdr; uint16_t e_minalloc; uint16_t e_maxalloc; uint16_t e_ss; uint16_t e_sp; uint16_t e_csum; uint16_t e_ip; uint16_t e_cs; uint16_t e_lfarlc; uint16_t e_ovno; uint16_t e_res[4]; uint16_t e_oemid; uint16_t e_oeminfo; uint16_t e_res2[10]; int32_t e_lfanew; };
struct IMAGE_FILE_HEADER_MIN { uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp; uint32_t PointerToSymbolTable; uint32_t NumberOfSymbols; uint16_t SizeOfOptionalHeader; uint16_t Characteristics; };
struct IMAGE_DATA_DIRECTORY_MIN { uint32_t VirtualAddress; uint32_t Size; };
struct IMAGE_OPTIONAL_HEADER64_MIN {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_MIN DataDirectory[16];
};
struct IMAGE_NT_HEADERS64_MIN { uint32_t Signature; IMAGE_FILE_HEADER_MIN FileHeader; IMAGE_OPTIONAL_HEADER64_MIN OptionalHeader; };
struct IMAGE_SECTION_HEADER_MIN {
    char Name[8];
    union { uint32_t PhysicalAddress; uint32_t VirtualSize; } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
#pragma pack(pop)

constexpr int IMAGE_DIRECTORY_ENTRY_SECURITY = 4;

// read file into memory
static std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return { std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>() };
}

static bool get_entrypoint_rva(const std::vector<uint8_t>& buf, uint32_t &entry_rva, uint64_t &image_base) {
    if (buf.size() < sizeof(IMAGE_DOS_HEADER_MIN)) return false;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER_MIN*>(buf.data());
    if (dos->e_magic != 0x5A4D) return false;
    size_t nt_off = static_cast<size_t>(dos->e_lfanew);
    if (nt_off + sizeof(IMAGE_NT_HEADERS64_MIN) > buf.size()) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64_MIN*>(buf.data() + nt_off);
    if (nt->Signature != 0x00004550) return false;
    entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    image_base = nt->OptionalHeader.ImageBase;
    return true;
}

static bool rva_to_file_offset(const std::vector<uint8_t>& buf, uint32_t rva, size_t &out_file_offset) {
    if (buf.size() < sizeof(IMAGE_DOS_HEADER_MIN)) return false;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER_MIN*>(buf.data());
    if (dos->e_magic != 0x5A4D) return false;
    size_t nt_off = static_cast<size_t>(dos->e_lfanew);
    if (nt_off + sizeof(IMAGE_NT_HEADERS64_MIN) > buf.size()) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64_MIN*>(buf.data() + nt_off);
    if (nt->Signature != 0x00004550) return false;
    const auto& fh = nt->FileHeader;
    size_t sec_off = nt_off + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER_MIN) + fh.SizeOfOptionalHeader;
    if (sec_off + static_cast<size_t>(fh.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER_MIN) > buf.size()) return false;
    auto sh = reinterpret_cast<const IMAGE_SECTION_HEADER_MIN*>(buf.data() + sec_off);
    for (int i = 0; i < fh.NumberOfSections; ++i) {
        uint32_t va = sh[i].VirtualAddress;
        uint32_t vs = sh[i].Misc.VirtualSize;
        uint32_t raw = sh[i].PointerToRawData;
        uint32_t rawsz = sh[i].SizeOfRawData;
        uint32_t sect_size = std::max<uint32_t>(vs, rawsz);
        if (rva >= va && rva < va + sect_size) {
            uint32_t delta = rva - va;
            out_file_offset = static_cast<size_t>(raw) + delta;
            if (out_file_offset >= buf.size()) return false;
            return true;
        }
    }
    // fallback: if rva within headers
    if (rva < buf.size()) { out_file_offset = rva; return true; }
    return false;
}

// Credit to illnyang | https://github.com/illnyang/steamstub_unpack/blob/trunk/src/main.cc
struct steamstub_header {
    uint32_t xor_key;
    uint32_t signature;
    uint64_t imagebase;
    uint64_t ep_addr;
    uint32_t bind_offset;
    uint32_t __pad1;
    uint64_t oep_addr;
    uint32_t __pad2;
    uint32_t payload_size;
    uint32_t drmpdll_off;
    uint32_t drmpdll_size;
    uint32_t appid;
    uint32_t flags;
    uint32_t bind_vsize;
    uint32_t __pad3;
    uint64_t code_addr;
    uint64_t code_rawsize;
    uint8_t aes_key[0x20];
    uint8_t aes_iv[0x10];
    uint8_t code_section_stolen[0x10];
    uint32_t drmp_encrypt_keys[0x4];
    uint32_t __pad4[0x8];
    uint64_t GetModuleHandleA_rva;
    uint64_t GetModuleHandleW_rva;
    uint64_t LoadLibraryA_rva;
    uint64_t LoadLibraryW_rva;
    uint64_t GetProcAddress_rva;
};
// ----------------------------------------------------------------------------------------

// Credit to illnyang | https://github.com/illnyang/steamstub_unpack/blob/trunk/src/main.cc
#define STUB_FLAG_NoModuleVerification 0x02
#define STUB_FLAG_NoEncryption 0x04
#define STUB_FLAG_NoOwnershipCheck 0x10
#define STUB_FLAG_NoDebuggerCheck 0x20
#define STUB_FLAG_NoErrorDialog 0x40
// ----------------------------------------------------------------------------------------

#define STUB_SIGNATURE 0xC0DEC0DFu
enum SteamStubVersion {
  Unknown,
  V1,
  V2,
  V3,
  V31,
  V312
};

int main(int argc, char** argv) {
    return 0;
}

// Extract .bind section.
bool extract_bind(std::vector<uint8_t> &file, size_t &section_size, size_t &section_offset) {
    auto dos2 = reinterpret_cast<IMAGE_DOS_HEADER_MIN*>(file.data());
    size_t nt_off2 = static_cast<size_t>(dos2->e_lfanew);
    auto nt2 = reinterpret_cast<IMAGE_NT_HEADERS64_MIN*>(file.data() + nt_off2);
    auto& fh2 = nt2->FileHeader;

    size_t sec_off2 = nt_off2 + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER_MIN) + fh2.SizeOfOptionalHeader;
    auto sh2 = reinterpret_cast<IMAGE_SECTION_HEADER_MIN*>(file.data() + sec_off2);

    int bind_idx = -1;
    for (int i = 0; i < fh2.NumberOfSections; ++i) {
        std::string name(sh2[i].Name, sh2[i].Name + 8);
        size_t z = name.find('\0'); if (z != std::string::npos) name.resize(z);
        if (name == ".bind") { std::cout << "[*] .bind section found\n"; bind_idx = i; break; }
    }

    // Assuming bind_idx is valid
    if (bind_idx != -1) {
        auto& bind_section = sh2[bind_idx];

        section_size = bind_section.SizeOfRawData;
        section_offset = bind_section.PointerToRawData;

        // Make sure offset + size does not exceed file size
        if (section_offset + section_size <= file.size()) {
            return true;
        }
    }
    
    std::cerr << "[-] No .bind section could be found\n";
    return false;
}

uint32_t CalculatePEChecksum(std::vector<uint8_t>& file) {
    if (file.size() < 0x100) return false; 
    // trivial sanity 
    uint8_t *base = file.data(); 
    size_t filesize = file.size(); 
    // Validate DOS header and NT headers offsets 
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER_MIN*>(base); 
    size_t nt_off = static_cast<size_t>(dos->e_lfanew); 
    if (nt_off + sizeof(IMAGE_NT_HEADERS64_MIN) > filesize) return false; 
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64_MIN*>(base + nt_off); 
    // Compute checksum field offset 
    size_t checksum_off = reinterpret_cast<uint8_t*>(&nt->OptionalHeader.CheckSum) - base; 
    if (checksum_off + sizeof(uint32_t) > filesize) return false;

    // Perform checksum
    uint64_t checksum = 0;
    uint64_t top = 0xFFFFFFFFULL;
    top++;

    // Walk file in DWORDs
    for (size_t i = 0; i + 3 < filesize; i += 4) {
        uint32_t dw = 0;
        std::memcpy(&dw, base + i, sizeof(dw));

        // Skip the CheckSum field
        if (i == checksum_off) continue;

        checksum = (checksum & 0xffffffffULL) + dw + (checksum >> 32);
        if (checksum > top) {
            checksum = (checksum & 0xffffffffULL) + (checksum >> 32);
        }
    }

    // Handle remaining bytes (if filesize not multiple of 4)
    size_t remainder = filesize & 3;
    if (remainder) {
        uint32_t last = 0;
        std::memcpy(&last, base + (filesize - remainder), remainder);
        if ((filesize - remainder) != checksum_off) {
            checksum = (checksum & 0xffffffffULL) + last + (checksum >> 32);
            if (checksum > top) {
                checksum = (checksum & 0xffffffffULL) + (checksum >> 32);
            }
        }
    }

    // Final folds
    checksum = (checksum & 0xffffULL) + (checksum >> 16);
    checksum = (checksum & 0xffffULL) + (checksum >> 16);
    checksum = checksum & 0xffffULL;

    checksum += static_cast<uint32_t>(filesize);

    return static_cast<uint32_t>(checksum);
}


// Get SteamStub version.
SteamStubVersion get_steamstub_version(std::vector<uint8_t> &bind_buffer) {
    // Check for SteamStub version.
    // Credit to atom0s for sigs | https://github.com/atom0s/Steamless/blob/master/Steamless.Unpacker.Variant31.x64/Main.cs

    // V3 base version.
    if (scan_signature(bind_buffer, "E8 00 00 00 00 50 53 51 52 56 57 55 41 50") != SIZE_MAX) {
        if (scan_signature(bind_buffer, "48 8D 91 ? ? ? ? 48") != SIZE_MAX) {
            std::cout << "[*] SteamStub v3.0.0\n";
            return V3;
        }
        else if (scan_signature(bind_buffer, "48 8D 91 ? ? ? ? 41") != SIZE_MAX) {
            std::cout << "[*] SteamStub v3.1.0\n";
            return V31;
        } 
        else if (scan_signature(bind_buffer, "48 C7 84 24 ? ? ? ? ? ? ? ? 48") != SIZE_MAX) {
            std::cout << "[*] SteamStub v3.1.2\n";
            return V312;
        }
        else {
            std::cout << "[*] Unknown SteamStub v3 version.\n"; 
            return Unknown;
        } 
    }
    else if (scan_signature(bind_buffer, "53 51 52 56 57 55 8B EC 81 EC 00 10 00 00 C7") != SIZE_MAX) {
        // V2 version.
        std::cerr << "[-] SteamStub v2.x (Not yet supported)\n";
        return V2;
    }
    else if (scan_signature(bind_buffer, "60 81 EC 00 10 00 00 BE ? ? ? ? B9 6A") != SIZE_MAX) {
        // V1 version.
        std::cerr << "[-] SteamStub v1.x (Not yet supported)\n";
        return V1;
    }
    else {
        std::cerr << "[*] Unknown SteamStub version.\n";
        return Unknown;
    }
}

// Store unpacked buffer
static std::vector<uint8_t> unpacked_buffer;

extern "C" {
    EMSCRIPTEN_KEEPALIVE // C++ function that can check the SteamStub version.
    int check_version_information(uint8_t* ptr, size_t size) {
        // Copy file buffer into vector
        std::vector<uint8_t> file(ptr, ptr + size);

        if (file.empty()) { std::cerr << "[-] Failed to read input file\n"; return 1; }
        std::cout << "[*] Read file, size = " << file.size() << " bytes\n";

        // Extract .bind section into its own buffer for faster scanning and less false positives.
        size_t section_size = -1;
        size_t section_offset = -1;
        if (!extract_bind(file, section_size, section_offset)) { return 0; }
        std::vector<uint8_t> bind_buffer(section_size);
        std::memcpy(bind_buffer.data(), file.data() + section_offset, section_size);
        return get_steamstub_version(bind_buffer);
    }

    EMSCRIPTEN_KEEPALIVE
    bool isUpdateChecksumChecked() {
        emscripten::val document = emscripten::val::global("document");
        emscripten::val checkbox = document.call<emscripten::val>("getElementById", std::string("updateChecksum"));
        return checkbox["checked"].as<bool>();
    }

    EMSCRIPTEN_KEEPALIVE
    bool isRemoveCertChecked() {
        emscripten::val document = emscripten::val::global("document");
        emscripten::val checkbox = document.call<emscripten::val>("getElementById", std::string("removeCert"));
        return checkbox["checked"].as<bool>();
    }

    EMSCRIPTEN_KEEPALIVE
    bool isKeepBindChecked() {
        emscripten::val document = emscripten::val::global("document");
        emscripten::val checkbox = document.call<emscripten::val>("getElementById", std::string("keepBind"));
        return checkbox["checked"].as<bool>();
    }

    // Called from JS with pointer to file buffer
    EMSCRIPTEN_KEEPALIVE
    int unpack_buffer(uint8_t* ptr, size_t size) {
        // Copy file buffer into vector
        std::vector<uint8_t> file(ptr, ptr + size);

        if (file.empty()) { std::cerr << "[-] Failed to read input file\n"; return 1; }
        std::cout << "[*] Read file, size = " << file.size() << " bytes\n";

        // Extract .bind section into its own buffer for faster scanning and less false positives.
        size_t section_size = -1;
        size_t section_offset = -1;
        if (!extract_bind(file, section_size, section_offset)) { return 1; }
        std::vector<uint8_t> bind_buffer(section_size);
        std::memcpy(bind_buffer.data(), file.data() + section_offset, section_size);

        SteamStubVersion steamstub_version = get_steamstub_version(bind_buffer);

        // Return here if version isn't supported.
        if (steamstub_version != V3 && steamstub_version != V31 && steamstub_version != V312) { return 1;}
        
        uint32_t ep_rva = 0; uint64_t image_base = 0;
        if (!get_entrypoint_rva(file, ep_rva, image_base)) { std::cerr << "[-] Failed to parse PE headers\n"; return 1; }
        std::cout << "[*] EntryPoint RVA = 0x" << std::hex << ep_rva << std::dec << "\n";
        std::cout << "[*] ImageBase = 0x" << std::hex << image_base << std::dec << "\n";

        const uint32_t header_offset_from_ep = 0xF0u;
        if (ep_rva < header_offset_from_ep) { std::cerr << "[-] EP RVA too small\n"; return 1; }
        uint32_t stub_rva = ep_rva - header_offset_from_ep;
        size_t stub_file_off = 0;
        if (!rva_to_file_offset(file, stub_rva, stub_file_off)) { std::cerr << "[-] Failed to map stub RVA to file offset\n"; return 1; }
        std::cout << "[*] Stub header RVA = 0x" << std::hex << stub_rva << " => file off 0x" << stub_file_off << std::dec << "\n";

        if (stub_file_off + sizeof(steamstub_header) > file.size()) { std::cerr << "[-] Stub header overruns file\n"; return 1; }
        std::vector<uint8_t> stub_bytes(sizeof(steamstub_header));
        memcpy(stub_bytes.data(), file.data() + stub_file_off, stub_bytes.size());

        std::cout << "[*] Rolling XOR unwrap of stub header\n";
        uint32_t key = *reinterpret_cast<uint32_t*>(stub_bytes.data());
        uint8_t* p = stub_bytes.data() + sizeof(uint32_t);
        uint8_t* endp = stub_bytes.data() + stub_bytes.size();
        while (p < endp) {
            uint32_t val = *reinterpret_cast<uint32_t*>(p);
            *reinterpret_cast<uint32_t*>(p) = val ^ key;
            key = val;
            p += sizeof(uint32_t);
        }

        auto* header = reinterpret_cast<steamstub_header*>(stub_bytes.data());
        std::cout << "[*] Stub signature (raw) = 0x" << std::hex << header->signature << std::dec << "\n";
        if (header->signature != STUB_SIGNATURE) { std::cerr << "[-] Stub signature mismatch\n"; return 1; }
        std::cout << "[*] Stub OK. AppID: " << header->appid << " Flags: 0x" << std::hex << header->flags << std::dec << "\n";
        std::cout << "[*] OEP Va: 0x" << std::hex << header->oep_addr << std::dec << " Code raw size: " << header->code_rawsize << "\n";

        bool noencrypt = (header->flags & STUB_FLAG_NoEncryption) != 0;
        std::cout << "[*] NoEncryption flag: " << (noencrypt ? "YES" : "NO") << "\n";

        if (!noencrypt) {
            // locate .text section
            auto dos = reinterpret_cast<const IMAGE_DOS_HEADER_MIN*>(file.data());
            size_t nt_off = static_cast<size_t>(dos->e_lfanew);
            auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64_MIN*>(file.data() + nt_off);
            const auto& fh = nt->FileHeader;
            size_t sec_off = nt_off + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER_MIN) + fh.SizeOfOptionalHeader;
            auto sh = reinterpret_cast<const IMAGE_SECTION_HEADER_MIN*>(file.data() + sec_off);

            const IMAGE_SECTION_HEADER_MIN* text_sh = nullptr;
            for (int i = 0; i < fh.NumberOfSections; ++i) {
                std::string name(sh[i].Name, sh[i].Name + 8);
                size_t z = name.find('\0'); if (z != std::string::npos) name.resize(z);
                if (name == ".text") { text_sh = &sh[i]; break; }
            }
            if (!text_sh) { std::cerr << "[-] .text section not found\n"; return 1; }

            std::cout << "[*] .text raw offset = 0x" << std::hex << text_sh->PointerToRawData
                    << " raw size = 0x" << text_sh->SizeOfRawData << std::dec << "\n";

            std::vector<uint8_t> v_code_bytes;
            v_code_bytes.insert(v_code_bytes.end(),
                            header->code_section_stolen,
                            header->code_section_stolen + sizeof(header->code_section_stolen));

            size_t text_ptr = static_cast<size_t>(text_sh->PointerToRawData);
            size_t text_sz  = static_cast<size_t>(text_sh->SizeOfRawData);
            if (text_ptr + text_sz > file.size()) { std::cerr << "[-] .text raw out of bounds\n"; return 1; }

            v_code_bytes.insert(v_code_bytes.end(), file.data() + text_ptr, file.data() + text_ptr + text_sz);
            std::cout << "[*] Total bytes to decrypt = " << v_code_bytes.size() << "\n";

            // Print AES Key found the SteamStub header.
            printAESKey(header->aes_key, 32);

            std::cout << "[*] Running AES-256 ECB decrypt on IV\n";
            AES256_ECB_decrypt(header->aes_iv, 16, header->aes_key);

            std::cout << "[*] Running AES-256 CBC decrypt on code bytes\n";
            size_t decrypt_len = (v_code_bytes.size() / 16) * 16;
            if (decrypt_len == 0) { std::cerr << "[-] Nothing to decrypt\n"; return 1; }

            AES256_CBC_decrypt(v_code_bytes.data(), decrypt_len, header->aes_key, header->aes_iv);

            // Remove PKCS#7 padding fromn decrypted section.
            pkcs7_unpad(v_code_bytes);

            // Write back decrypted section and restore stolen bytes at the start (to match original binary size)
            size_t steal_sz = sizeof(header->code_section_stolen);
            if (decrypt_len < steal_sz) {
                std::cerr << "[-] Decrypted length too small\n";
                return 1;
            }

            // Add the stolen bytes
            memcpy(file.data() + text_ptr, header->code_section_stolen, steal_sz);

            // Then put the rest of the decrypted bytes
            size_t copy_sz = std::min<size_t>(text_sz - steal_sz, decrypt_len - steal_sz);
            memcpy(file.data() + text_ptr + steal_sz, v_code_bytes.data() + steal_sz, copy_sz);

            std::cout << "[*] Restored stolen bytes and wrote " << (steal_sz + copy_sz)
                    << " decrypted .text bytes\n";
        }

        // Update AddressOfEntryPoint with OEP (convert VA -> RVA using image_base)
        if (header->oep_addr != 0 && image_base != 0) {
            uint32_t new_ep_rva = 0;
            if (header->oep_addr >= image_base) {
                // oep_addr is VA
                new_ep_rva = static_cast<uint32_t>(header->oep_addr - image_base);
            } else {
                // oep_addr is already RVA
                new_ep_rva = static_cast<uint32_t>(header->oep_addr);
            }
            auto dos2 = reinterpret_cast<IMAGE_DOS_HEADER_MIN*>(file.data());
            size_t nt_off2 = static_cast<size_t>(dos2->e_lfanew);
            auto nt2 = reinterpret_cast<IMAGE_NT_HEADERS64_MIN*>(file.data() + nt_off2);
            nt2->OptionalHeader.AddressOfEntryPoint = new_ep_rva;
            std::cout << "[*] Updated AddressOfEntryPoint to 0x" << std::hex << new_ep_rva << std::dec << "\n";
        } else {
            std::cout << "[*] Skipping EP update (missing values)\n";
        }

        // Remove .bind section
        {
            auto dos2 = reinterpret_cast<IMAGE_DOS_HEADER_MIN*>(file.data());
            size_t nt_off2 = static_cast<size_t>(dos2->e_lfanew);
            auto nt2 = reinterpret_cast<IMAGE_NT_HEADERS64_MIN*>(file.data() + nt_off2);
            auto& fh2 = nt2->FileHeader;

            size_t sec_off2 = nt_off2 + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER_MIN) + fh2.SizeOfOptionalHeader;
            auto sh2 = reinterpret_cast<IMAGE_SECTION_HEADER_MIN*>(file.data() + sec_off2);

            int bind_idx = -1;
            for (int i = 0; i < fh2.NumberOfSections; ++i) {
                std::string name(sh2[i].Name, sh2[i].Name + 8);
                size_t z = name.find('\0'); if (z != std::string::npos) name.resize(z);
                if (name == ".bind") { bind_idx = i; break; }
            }

            if (bind_idx >= 0) {
                std::cout << "[*] .bind section found at index " << bind_idx << "\n";
                if (isKeepBindChecked() == false) {
                    std::cout << "[*] Removing .bind section at index " << bind_idx << "\n";

                    // shift all later sections left to overwrite .bind
                    for (int i = bind_idx; i + 1 < fh2.NumberOfSections; ++i) {
                        sh2[i] = sh2[i + 1];
                    }

                    // decrement number of sections
                    fh2.NumberOfSections--;

                    // recompute SizeOfImage: last section end aligned to SectionAlignment
                    uint32_t max_end = 0;
                    for (int i = 0; i < fh2.NumberOfSections; ++i) {
                        uint32_t end = sh2[i].VirtualAddress + sh2[i].Misc.VirtualSize;
                        if (end > max_end) max_end = end;
                    }
                    uint32_t align = nt2->OptionalHeader.SectionAlignment;
                    nt2->OptionalHeader.SizeOfImage = (max_end + align - 1) & ~(align - 1);

                    std::cout << "[*] Updated NumberOfSections = " << fh2.NumberOfSections
                            << " SizeOfImage = 0x" << std::hex << nt2->OptionalHeader.SizeOfImage << std::dec << "\n";
                } else {
                    std::cout << "[*] Keeping .bind section at index " << bind_idx << " by user request" << "\n";
                }
                
            } else {
                std::cout << "[-] .bind section not found, nothing to remove\n";
            }
        }

        // Remove certificate table / ntHeaders->OptionalHeader.DataDirectory[4]
        {
            auto dos2 = reinterpret_cast<IMAGE_DOS_HEADER_MIN*>(file.data());
            size_t nt_off2 = static_cast<size_t>(dos2->e_lfanew);
            auto nt2 = reinterpret_cast<IMAGE_NT_HEADERS64_MIN*>(file.data() + nt_off2);
            uint32_t numDirs = nt2->OptionalHeader.NumberOfRvaAndSizes;
            if (numDirs <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
                std::cout << "[*] No certificate directory entry\n";
                // Nothing to clear
            }
            else {
                IMAGE_DATA_DIRECTORY_MIN &certDir = nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
                uint32_t origVA = certDir.VirtualAddress;
                uint32_t origSize = certDir.Size;

                if (origVA == 0 && origSize == 0) {
                    std::cout << "[*] Certificate table already empty\n";
                } else {
                    std::cout << "[*] Certificate table present: VA=" << origVA << " Size=" << origSize << '\n';

                    if (isRemoveCertChecked() == true) {
                        // Clear the data directory [4] fields
                        certDir.VirtualAddress = 0;
                        certDir.Size = 0;
                        std::cout << "[*] Certificate table cleared, by user request\n";
                    } else {
                        std::cout << "[*] Certificate table NOT cleared, by user request\n";
                    } 
                }
            }
        }

        // Update PE Checksum (OptionalHeader.CheckSum)
        if (isUpdateChecksumChecked() == true) {
            uint32_t newChecksum = CalculatePEChecksum(file);

            auto dos = reinterpret_cast<IMAGE_DOS_HEADER_MIN*>(file.data());
            auto nt = reinterpret_cast<IMAGE_NT_HEADERS64_MIN*>(file.data() + dos->e_lfanew);
            nt->OptionalHeader.CheckSum = newChecksum;

            std::cout << "[*] Updated checksum to 0x" << std::hex << newChecksum << std::dec << "\n";
        } else {
            std::cout << "[*] Keeping old checksum by user request\n";
        }

        // For final, move unpacked file to unpacked_buffer.
        unpacked_buffer = std::move(file);
        return 0;
    }

    // Function for JS to fetch buffer pointer + size
    EMSCRIPTEN_KEEPALIVE
    uint8_t* get_unpacked_ptr() { return unpacked_buffer.data(); }

    EMSCRIPTEN_KEEPALIVE
    size_t get_unpacked_size() { return unpacked_buffer.size(); }

    // Example JS save call
    EM_JS(void, open_file_js, (), {
        const input = document.createElement('input');
        input.type = 'file';
        input.onchange = async(e) =>
        {
            const file = e.target.files && e.target.files[0];
            console.log(file.name);
            await loadExecutableBuffer(file);
        };
    });

    EMSCRIPTEN_KEEPALIVE
    void open_file() {
        open_file_js();
    }

}

