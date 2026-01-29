#pragma once
// ------------------------------------------------------------------------- //
//  Self-contained SteamStub v3 unpacker By GHFear @ IllusorySoftware        //
//  Version 0.1.8                                                            //
//  Compatible with Emscripten (drop the emsdk folder next to this file and  //
//  compile with the included compile script for linux)                      //
// ------------------------------------------------------------------------- //
//  Lots of credit to Cyanic (aka Golem_x86), atom0s and illnyang for prior  //
//  research on steamstub drm.                                               //
//  Without y'all, this wouldn't be possible.                                //
// ------------------------------------------------------------------------- //
#include "ReadWrite/RW.h"

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

enum SteamStubVersion {
  Unknown,
  x86_V10,
  x86_V20,
  x86_V21,
  x86_V30,
  x86_V310,
  x86_V311,
  x86_V312,
  x64_V30,
  x64_V310,
  x64_V311,
  x64_V312
};

// Get SteamStub version.
SteamStubVersion get_steamstub_version(std::vector<uint8_t> &bind_buffer) {
    // Check for SteamStub version.
    // Credit to atom0s for sigs | https://github.com/atom0s/Steamless/blob/master/Steamless.Unpacker.Variant31.x64/Main.cs

    // V3 x64 base version.
    if (scan_signature(bind_buffer, "E8 00 00 00 00 50 53 51 52 56 57 55 41 50") != SIZE_MAX) {
        if (scan_signature(bind_buffer, "48 8D 91 ? ? ? ? 48") != SIZE_MAX) {
            std::cout << "[*] SteamStub v3.0.0 x64\n";
            return x64_V30;
        }
        else if (scan_signature(bind_buffer, "48 8D 91 ? ? ? ? 41") != SIZE_MAX) {
            std::cout << "[*] SteamStub v3.1.0 x64\n";
            return x64_V310;
        } 
        else if (scan_signature(bind_buffer, "48 C7 84 24 ? ? ? ? ? ? ? ? 48") != SIZE_MAX) {
            std::cout << "[*] SteamStub v3.1.2 x64\n";
            return x64_V312;
        }
        else {
            std::cout << "[-] Unknown SteamStub v3 x64 version.\n"; 
            return Unknown;
        } 
    }
    else if (scan_signature(bind_buffer, "E8 00 00 00 00 50 53 51 52 56 57 55 8B 44 24 1C 2D 05 00 00 00 8B CC 83 E4 F0 51 51 51 50") != SIZE_MAX) {
        // V3 x86 base version.
        if (size_t offset = scan_signature(bind_buffer, "55 8B EC 81 EC ? ? ? ? 53 ? ? ? ? ? 68"); offset != SIZE_MAX) {
            uint64_t header_size = VectorRW::read_u32_le(bind_buffer, offset + 0x10);
            std::cout << "[*] Stub header size = " << header_size << "\n";
            if (header_size == 0xF0)
            {
                // We are confirmed 3.1.0 x86
                std::cerr << "[-] SteamStub v3.1.0 x86 (Not yet supported)\n";
                return x86_V310;
            }
            else if (header_size == 0xD0 || header_size == 0xB0)
            {
                // We are confirmed 3.0.0 x86
                std::cerr << "[-] SteamStub v3.0.0 x86 (Not yet supported)\n";
                return x86_V30;
            }
            
            std::cout << "[-] Unknown SteamStub v3 x86 version.\n"; 
            return Unknown;
        }
        else if (size_t offset = scan_signature(bind_buffer, "55 8B EC 81 EC ? ? ? ? 53 ? ? ? ? ? 8D 83"); offset != SIZE_MAX) {
            uint64_t header_size = VectorRW::read_u32_le(bind_buffer, offset + 0x16);
            std::cout << "[*] Stub header size = " << header_size << "\n";
            if (header_size == 0xF0)
            {
                // We are confirmed 3.1.1 x86
                std::cerr << "[-] SteamStub v3.1.1 x86 (Not yet supported)\n";
                return x86_V311;
            }
            else if (header_size == 0xD0 || header_size == 0xB0)
            {
                // We are confirmed 3.0.0 x86
                std::cerr << "[-] SteamStub v3.0.0 x86 (Not yet supported)\n";
                return x86_V30;
            }
            std::cout << "[-] Unknown SteamStub v3 x86 version.\n"; 
            return Unknown;
        } 
        else if (size_t offset = scan_signature(bind_buffer, "55 8B EC 81 EC ? ? ? ? 56 ? ? ? ? ? ? ? ? ? ? 8D"); offset != SIZE_MAX) {
            uint64_t header_size = VectorRW::read_u32_le(bind_buffer, offset + 0x10);
            std::cout << "[*] Stub header size = " << header_size << "\n";
            if (header_size == 0xF0)
            {
                // We are confirmed 3.1.2 x86
                std::cerr << "[-] SteamStub v3.1.2 x86 (Not yet supported)\n";
                return x86_V312;
            }
            std::cout << "[-] Unknown SteamStub v3 x86 version.\n"; 
            return Unknown;
        }
        else {
            std::cerr << "[-] Unknown SteamStub v3 x86 version.\n"; 
            return Unknown;
        } 
    }
    else if (scan_signature(bind_buffer, "53 51 52 56 57 55 8B EC 81 EC 00 10 00 00 C7") != SIZE_MAX) {
        // V21 x86 version.
        std::cerr << "[-] SteamStub v2.1 x86 (Not yet supported)\n";
        return x86_V21;
    }
    else if (scan_signature(bind_buffer, "53 51 52 56 57 55 8B EC 81 EC 00 10 00 00 BE") != SIZE_MAX) {
        // V20 x86 version
        std::cerr << "[-] SteamStub v2.0 x86 (Not yet supported)\n";
        return x86_V20;
    }
    else if (scan_signature(bind_buffer, "60 81 EC 00 10 00 00 BE ? ? ? ? B9 6A") != SIZE_MAX) {
        // V10 x86 version.
        std::cerr << "[-] SteamStub v1.0 x86 (Not yet supported)\n";
        return x86_V10;
    }
    else {
        std::cerr << "[-] Unknown SteamStub version.\n";
        return Unknown;
    }
}