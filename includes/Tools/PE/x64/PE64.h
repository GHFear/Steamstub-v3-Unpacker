#pragma once
// ------------------------------------------------------------------------- //
//  Self-contained SteamStub v3 unpacker By GHFear @ IllusorySoftware        //
//  Object-oriented PE64 helpers                                             //
// ------------------------------------------------------------------------- //

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

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

    class Image
    {
    public:
        explicit Image(std::vector<uint8_t>& buffer)
            : buffer_(buffer)
        {
        }

        explicit Image(const std::vector<uint8_t>& buffer)
            : buffer_(const_cast<std::vector<uint8_t>&>(buffer))
        {
        }

        bool getEntryPoint(uint32_t& entryRva, uint64_t& imageBase) const
        {
            const auto* nt = ntHeaders();
            if (!nt) {
                return false;
            }

            entryRva = nt->OptionalHeader.AddressOfEntryPoint;
            imageBase = nt->OptionalHeader.ImageBase;
            return true;
        }

        bool rvaToFileOffset(uint32_t rva, size_t& outFileOffset) const
        {
            const auto* nt = ntHeaders();
            if (!nt) {
                return false;
            }

            const auto& fh = nt->FileHeader;
            const auto* sh = sectionHeaders();
            if (!sh) {
                return false;
            }

            for (int i = 0; i < fh.NumberOfSections; ++i) {
                const uint32_t va = sh[i].VirtualAddress;
                const uint32_t vs = sh[i].Misc.VirtualSize;
                const uint32_t raw = sh[i].PointerToRawData;
                const uint32_t rawsz = sh[i].SizeOfRawData;
                const uint32_t sectSize = std::max<uint32_t>(vs, rawsz);
                if (rva >= va && rva < va + sectSize) {
                    const uint32_t delta = rva - va;
                    outFileOffset = static_cast<size_t>(raw) + delta;
                    return outFileOffset < buffer_.size();
                }
            }

            if (rva < buffer_.size()) {
                outFileOffset = rva;
                return true;
            }

            return false;
        }

        bool extractBindSection(size_t& sectionSize, size_t& sectionOffset) const
        {
            const IMAGE_SECTION_HEADER_MIN* bindSection = findSection(".bind");
            if (!bindSection) {
                std::cerr << "[-] No .bind section could be found\n";
                return false;
            }

            std::cout << "[*] .bind section found\n";
            sectionSize = bindSection->SizeOfRawData;
            sectionOffset = bindSection->PointerToRawData;

            if (sectionOffset + sectionSize <= buffer_.size()) {
                return true;
            }

            std::cerr << "[-] .bind section is out of bounds\n";
            return false;
        }

        const IMAGE_SECTION_HEADER_MIN* findSection(const std::string& requestedName) const
        {
            const auto* nt = ntHeaders();
            const auto* sh = sectionHeaders();
            if (!nt || !sh) {
                return nullptr;
            }

            for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if (sectionName(sh[i]) == requestedName) {
                    return &sh[i];
                }
            }

            return nullptr;
        }

        IMAGE_SECTION_HEADER_MIN* mutableSectionHeaders()
        {
            auto* nt = ntHeaders();
            if (!nt) {
                return nullptr;
            }

            const size_t secOff = sectionHeaderOffset();
            const size_t count = nt->FileHeader.NumberOfSections;
            if (secOff + count * sizeof(IMAGE_SECTION_HEADER_MIN) > buffer_.size()) {
                return nullptr;
            }

            return reinterpret_cast<IMAGE_SECTION_HEADER_MIN*>(buffer_.data() + secOff);
        }

        IMAGE_NT_HEADERS64_MIN* ntHeaders()
        {
            if (buffer_.size() < sizeof(IMAGE_DOS_HEADER_MIN)) {
                return nullptr;
            }

            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_MIN*>(buffer_.data());
            if (dos->e_magic != 0x5A4D || dos->e_lfanew < 0) {
                return nullptr;
            }

            const size_t ntOff = static_cast<size_t>(dos->e_lfanew);
            if (ntOff + sizeof(IMAGE_NT_HEADERS64_MIN) > buffer_.size()) {
                return nullptr;
            }

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64_MIN*>(buffer_.data() + ntOff);
            if (nt->Signature != 0x00004550) {
                return nullptr;
            }

            return nt;
        }

        const IMAGE_NT_HEADERS64_MIN* ntHeaders() const
        {
            return const_cast<Image*>(this)->ntHeaders();
        }

        const IMAGE_SECTION_HEADER_MIN* sectionHeaders() const
        {
            const auto* nt = ntHeaders();
            if (!nt) {
                return nullptr;
            }

            const size_t secOff = sectionHeaderOffset();
            const size_t count = nt->FileHeader.NumberOfSections;
            if (secOff + count * sizeof(IMAGE_SECTION_HEADER_MIN) > buffer_.size()) {
                return nullptr;
            }

            return reinterpret_cast<const IMAGE_SECTION_HEADER_MIN*>(buffer_.data() + secOff);
        }

        uint32_t calculateChecksum()
        {
            if (buffer_.size() < 0x100) {
                return 0;
            }

            uint8_t* base = buffer_.data();
            const size_t filesize = buffer_.size();
            auto* nt = ntHeaders();
            if (!nt) {
                return 0;
            }

            const size_t checksumOff = reinterpret_cast<uint8_t*>(&nt->OptionalHeader.CheckSum) - base;
            if (checksumOff + sizeof(uint32_t) > filesize) {
                return 0;
            }

            uint64_t checksum = 0;
            uint64_t top = 0xFFFFFFFFULL;
            top++;

            for (size_t i = 0; i + 3 < filesize; i += 4) {
                uint32_t dw = 0;
                std::memcpy(&dw, base + i, sizeof(dw));

                if (i == checksumOff) {
                    continue;
                }

                checksum = (checksum & 0xffffffffULL) + dw + (checksum >> 32);
                if (checksum > top) {
                    checksum = (checksum & 0xffffffffULL) + (checksum >> 32);
                }
            }

            const size_t remainder = filesize & 3;
            if (remainder) {
                uint32_t last = 0;
                std::memcpy(&last, base + (filesize - remainder), remainder);
                if ((filesize - remainder) != checksumOff) {
                    checksum = (checksum & 0xffffffffULL) + last + (checksum >> 32);
                    if (checksum > top) {
                        checksum = (checksum & 0xffffffffULL) + (checksum >> 32);
                    }
                }
            }

            checksum = (checksum & 0xffffULL) + (checksum >> 16);
            checksum = (checksum & 0xffffULL) + (checksum >> 16);
            checksum &= 0xffffULL;
            checksum += static_cast<uint32_t>(filesize);

            return static_cast<uint32_t>(checksum);
        }

        static std::string sectionName(const IMAGE_SECTION_HEADER_MIN& section)
        {
            std::string name(section.Name, section.Name + 8);
            const size_t z = name.find('\0');
            if (z != std::string::npos) {
                name.resize(z);
            }
            return name;
        }

    private:
        size_t ntHeaderOffset() const
        {
            if (buffer_.size() < sizeof(IMAGE_DOS_HEADER_MIN)) {
                return 0;
            }

            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER_MIN*>(buffer_.data());
            return dos->e_lfanew < 0 ? 0 : static_cast<size_t>(dos->e_lfanew);
        }

        size_t sectionHeaderOffset() const
        {
            const auto* nt = ntHeaders();
            if (!nt) {
                return 0;
            }

            return ntHeaderOffset() + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER_MIN) + nt->FileHeader.SizeOfOptionalHeader;
        }

        std::vector<uint8_t>& buffer_;
    };

    inline bool get_entrypoint_rva(const std::vector<uint8_t>& buf, uint32_t& entry_rva, uint64_t& image_base)
    {
        return Image(buf).getEntryPoint(entry_rva, image_base);
    }

    inline bool rva_to_file_offset(const std::vector<uint8_t>& buf, uint32_t rva, size_t& out_file_offset)
    {
        return Image(buf).rvaToFileOffset(rva, out_file_offset);
    }

    inline bool extract_bind(std::vector<uint8_t>& file, size_t& section_size, size_t& section_offset)
    {
        return Image(file).extractBindSection(section_size, section_offset);
    }

    inline uint32_t CalculatePEChecksum(std::vector<uint8_t>& file)
    {
        return Image(file).calculateChecksum();
    }
}
