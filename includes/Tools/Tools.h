#pragma once
// ------------------------------------------------------------------------- //
//  Self-contained SteamStub v3 unpacker By GHFear @ IllusorySoftware        //
//  Compatible with Emscripten (drop the emsdk folder next to this file and  //
//  compile with the included compile script for linux)                      //
// ------------------------------------------------------------------------- //
//  Lots of credit to Cyanic (aka Golem_x86), atom0s and illnyang for prior  //
//  research on steamstub drm.                                               //
//  Without y'all, this wouldn't be possible.                                //
// ------------------------------------------------------------------------- //

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include "ReadWrite/RW.h"

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

namespace SteamStub
{
    class AesKeyFormatter
    {
    public:
        static void print(const uint8_t* key, size_t size)
        {
            std::cout << "[*] SteamStub AES Key: 0x";
            for (size_t i = 0; i < size; ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key[i]);
            }
            std::cout << std::dec << "\n";
        }
    };

    class IdaSignature
    {
    public:
        explicit IdaSignature(std::string signature)
            : signature_(std::move(signature))
        {
            valid_ = parse();
        }

        bool valid() const { return valid_; }
        const std::vector<uint8_t>& pattern() const { return pattern_; }
        const std::vector<bool>& mask() const { return mask_; }

    private:
        bool parse()
        {
            std::istringstream iss(signature_);
            std::string token;
            while (iss >> token) {
                if (token == "?") {
                    pattern_.push_back(0x00);
                    mask_.push_back(false);
                } else if (token.size() == 2 &&
                           std::isxdigit(static_cast<unsigned char>(token[0])) &&
                           std::isxdigit(static_cast<unsigned char>(token[1]))) {
                    pattern_.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
                    mask_.push_back(true);
                } else {
                    return false;
                }
            }
            return !pattern_.empty();
        }

        std::string signature_;
        std::vector<uint8_t> pattern_;
        std::vector<bool> mask_;
        bool valid_ = false;
    };

    class SignatureScanner
    {
    public:
        explicit SignatureScanner(const std::vector<uint8_t>& buffer)
            : buffer_(buffer)
        {
        }

        size_t find(const std::string& idaSignature) const
        {
            IdaSignature signature(idaSignature);
            if (!signature.valid()) {
                return notFound();
            }

            const size_t bufSize = buffer_.size();
            const size_t patSize = signature.pattern().size();
            if (patSize == 0 || bufSize < patSize) {
                return notFound();
            }

            for (size_t i = 0; i <= bufSize - patSize; ++i) {
                bool match = true;
                for (size_t j = 0; j < patSize; ++j) {
                    if (signature.mask()[j] && buffer_[i + j] != signature.pattern()[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return i;
                }
            }

            return notFound();
        }

        static constexpr size_t notFound()
        {
            return std::numeric_limits<size_t>::max();
        }

    private:
        const std::vector<uint8_t>& buffer_;
    };

    class Pkcs7Padding
    {
    public:
        static size_t unpad(std::vector<uint8_t>& buf)
        {
            if (buf.empty()) {
                return 0;
            }

            const uint8_t pad = buf.back();
            if (pad == 0 || pad > 16 || pad > buf.size()) {
                return buf.size();
            }

            for (size_t i = 0; i < pad; ++i) {
                if (buf[buf.size() - 1 - i] != pad) {
                    return buf.size();
                }
            }

            buf.resize(buf.size() - pad);
            return buf.size();
        }
    };

    class SteamStubVersionDetector
    {
    public:
        SteamStubVersion detect(const std::vector<uint8_t>& bindBuffer) const
        {
            SignatureScanner scanner(bindBuffer);

            // Check for SteamStub version.
            // Credit to atom0s for sigs | https://github.com/atom0s/Steamless/blob/master/Steamless.Unpacker.Variant31.x64/Main.cs

            // V3 x64 base version.
            if (scanner.find("E8 00 00 00 00 50 53 51 52 56 57 55 41 50") != SignatureScanner::notFound()) {
                if (scanner.find("48 8D 91 ? ? ? ? 48") != SignatureScanner::notFound()) {
                    std::cout << "[*] SteamStub v3.0.0 x64\n";
                    return x64_V30;
                }
                if (scanner.find("48 8D 91 ? ? ? ? 41") != SignatureScanner::notFound()) {
                    std::cout << "[*] SteamStub v3.1.0 x64\n";
                    return x64_V310;
                }
                if (scanner.find("48 C7 84 24 ? ? ? ? ? ? ? ? 48") != SignatureScanner::notFound()) {
                    std::cout << "[*] SteamStub v3.1.2 x64\n";
                    return x64_V312;
                }

                std::cout << "[-] Unknown SteamStub v3 x64 version.\n";
                return Unknown;
            }

            // V3 x86 base version.
            if (scanner.find("E8 00 00 00 00 50 53 51 52 56 57 55 8B 44 24 1C 2D 05 00 00 00 8B CC 83 E4 F0 51 51 51 50") != SignatureScanner::notFound()) {
                size_t offset = scanner.find("55 8B EC 81 EC ? ? ? ? 53 ? ? ? ? ? 68");
                if (offset != SignatureScanner::notFound()) {
                    const uint64_t headerSize = VectorRW::read_u32_le(bindBuffer, offset + 0x10);
                    std::cout << "[*] Stub header size = " << headerSize << "\n";
                    if (headerSize == 0xF0) {
                        std::cerr << "[-] SteamStub v3.1.0 x86 (Not yet supported)\n";
                        return x86_V310;
                    }
                    if (headerSize == 0xD0 || headerSize == 0xB0) {
                        std::cerr << "[-] SteamStub v3.0.0 x86 (Not yet supported)\n";
                        return x86_V30;
                    }

                    std::cout << "[-] Unknown SteamStub v3 x86 version.\n";
                    return Unknown;
                }

                offset = scanner.find("55 8B EC 81 EC ? ? ? ? 53 ? ? ? ? ? 8D 83");
                if (offset != SignatureScanner::notFound()) {
                    const uint64_t headerSize = VectorRW::read_u32_le(bindBuffer, offset + 0x16);
                    std::cout << "[*] Stub header size = " << headerSize << "\n";
                    if (headerSize == 0xF0) {
                        std::cerr << "[-] SteamStub v3.1.1 x86 (Not yet supported)\n";
                        return x86_V311;
                    }
                    if (headerSize == 0xD0 || headerSize == 0xB0) {
                        std::cerr << "[-] SteamStub v3.0.0 x86 (Not yet supported)\n";
                        return x86_V30;
                    }

                    std::cout << "[-] Unknown SteamStub v3 x86 version.\n";
                    return Unknown;
                }

                offset = scanner.find("55 8B EC 81 EC ? ? ? ? 56 ? ? ? ? ? ? ? ? ? ? 8D");
                if (offset != SignatureScanner::notFound()) {
                    const uint64_t headerSize = VectorRW::read_u32_le(bindBuffer, offset + 0x10);
                    std::cout << "[*] Stub header size = " << headerSize << "\n";
                    if (headerSize == 0xF0) {
                        std::cerr << "[-] SteamStub v3.1.2 x86 (Not yet supported)\n";
                        return x86_V312;
                    }

                    std::cout << "[-] Unknown SteamStub v3 x86 version.\n";
                    return Unknown;
                }

                std::cerr << "[-] Unknown SteamStub v3 x86 version.\n";
                return Unknown;
            }

            if (scanner.find("53 51 52 56 57 55 8B EC 81 EC 00 10 00 00 C7") != SignatureScanner::notFound()) {
                std::cerr << "[-] SteamStub v2.1 x86 (Not yet supported)\n";
                return x86_V21;
            }

            if (scanner.find("53 51 52 56 57 55 8B EC 81 EC 00 10 00 00 BE") != SignatureScanner::notFound()) {
                std::cerr << "[-] SteamStub v2.0 x86 (Not yet supported)\n";
                return x86_V20;
            }

            if (scanner.find("60 81 EC 00 10 00 00 BE ? ? ? ? B9 6A") != SignatureScanner::notFound()) {
                std::cerr << "[-] SteamStub v1.0 x86 (Not yet supported)\n";
                return x86_V10;
            }

            std::cerr << "[-] Unknown SteamStub version.\n";
            return Unknown;
        }
    };

}

// Backwards-compatible wrappers for older call sites.
inline void printAESKey(const uint8_t* key, size_t size)
{
    SteamStub::AesKeyFormatter::print(key, size);
}

inline bool parse_ida_signature(const std::string& sig, std::vector<uint8_t>& pattern, std::vector<bool>& mask)
{
    SteamStub::IdaSignature signature(sig);
    if (!signature.valid()) {
        return false;
    }

    pattern = signature.pattern();
    mask = signature.mask();
    return true;
}

inline size_t scan_signature(const std::vector<uint8_t>& buffer, const std::string& ida_sig)
{
    return SteamStub::SignatureScanner(buffer).find(ida_sig);
}

inline size_t pkcs7_unpad(std::vector<uint8_t>& buf)
{
    return SteamStub::Pkcs7Padding::unpad(buf);
}

inline SteamStubVersion get_steamstub_version(std::vector<uint8_t>& bind_buffer)
{
    return SteamStub::SteamStubVersionDetector().detect(bind_buffer);
}

inline SteamStubVersion get_steamstub_version(const std::vector<uint8_t>& bind_buffer)
{
    return SteamStub::SteamStubVersionDetector().detect(bind_buffer);
}
