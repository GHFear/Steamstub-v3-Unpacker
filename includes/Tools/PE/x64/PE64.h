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
#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream> 
#include <variant>

namespace PE64 
{
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
};

