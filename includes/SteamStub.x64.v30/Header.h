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
#include "Flags.h"
#include "../Steam/Decryption/Decryption.h"

namespace SteamStub_x64_v30
{
    // Credit to atom0s for header.
    #pragma pack(push, 1)
    struct StubHeader
    {
        uint32_t xor_key;
        uint32_t signature;
        uint64_t imagebase;
        uint32_t ep_addr;
        uint32_t bind_offset;
        uint32_t __pad0;
        uint32_t oep_addr;
        uint32_t __pad1;
        uint32_t payload_size;
        uint32_t drmpdll_off;
        uint32_t drmpdll_size;
        uint32_t appid;
        uint32_t flags;
        uint32_t bind_vsize;
        uint32_t __pad2;
        uint32_t code_addr;
        uint32_t code_rawsize;
        uint8_t  aes_key[0x20];
        uint8_t  aes_iv[0x10];
        uint8_t  code_section_stolen[0x10];
        uint32_t drmp_encrypt_keys[0x4];
        uint32_t has_tls_callback;
        uint32_t __pad3;
        uint32_t __pad4;
        uint32_t __pad5;
        uint32_t __pad6;
        uint32_t __pad7;
        uint32_t GetModuleHandleA_rva;
        uint32_t GetModuleHandleW_rva;
        uint32_t LoadLibraryA_rva;
        uint32_t LoadLibraryW_rva;
        uint32_t GetProcAddress_rva;
        uint32_t __pad8;
        uint32_t __pad9;
        uint32_t __pad10;
    };
    #pragma pack(pop)

    int UnpackSteamDRMPDLL(StubHeader* header, uint32_t ep_rva, std::vector<uint8_t>& file) {
        if (header->drmpdll_size == 0) {
            std::cout << "[*] This exe doesn't have an embedded SteamDRMP.dll\n";
            return 0;
        } else {
            std::cout << "[*] This exe has an embedded SteamDRMP.dll\n";
            std::cout << "[*] SteamDRMP.dll offset: 0x" << std::hex << header->drmpdll_off << std::dec << "\n";
            std::cout << "[*] SteamDRMP.dll size: 0x" << std::hex << header->drmpdll_size << std::dec << "\n";
            std::cout << "[*] SteamDRMP.dll encryption key[0]: 0x" << std::hex << header->drmp_encrypt_keys[0] << std::dec << "\n";
            std::cout << "[*] SteamDRMP.dll encryption key[1]: 0x" << std::hex << header->drmp_encrypt_keys[1] << std::dec << "\n";
            std::cout << "[*] SteamDRMP.dll encryption key[2]: 0x" << std::hex << header->drmp_encrypt_keys[2] << std::dec << "\n";
            std::cout << "[*] SteamDRMP.dll encryption key[3]: 0x" << std::hex << header->drmp_encrypt_keys[3] << std::dec << "\n";
            if (isDumpDRMPChecked())
            {
                std::cout << "[*] You chose to unpack the embedded SteamDRMP.dll\n";
                size_t drmp_off = 0;
                uint32_t drmp_rva = ep_rva - header->bind_offset + header->drmpdll_off;
                if (!PE64::rva_to_file_offset(file, drmp_rva, drmp_off)) { std::cerr << "[-] Failed to map DRMP RVA to file offset\n"; return 1; }
                std::vector<uint8_t> drmpData(header->drmpdll_size);
                std::memcpy(drmpData.data(), file.data() + drmp_off, drmpData.size());
                Steam::Decryption::XTEAPass1(drmpData, header->drmp_encrypt_keys);
                unpackedDRMP_buffer = std::move(drmpData);
                return 0;
            } else {
                std::cout << "[*] You chose not to unpack the embedded SteamDRMP.dll\n";
                return 0;
            }
        }
        return 0;
    }

    // Unpack protected .text (compiled code) section.
    int UnpackCodeSection(std::vector<uint8_t>& file) {
        uint32_t ep_rva = 0; uint64_t image_base = 0;
        if (!PE64::get_entrypoint_rva(file, ep_rva, image_base)) { std::cerr << "[-] Failed to parse PE headers\n"; return 1; }
        std::cout << "[*] EntryPoint RVA = 0x" << std::hex << ep_rva << std::dec << "\n";
        std::cout << "[*] ImageBase = 0x" << std::hex << image_base << std::dec << "\n";

        const uint32_t header_offset_from_ep = 0xF0u;
        if (ep_rva < header_offset_from_ep) { std::cerr << "[-] EP RVA too small\n"; return 1; }
        uint32_t stub_rva = ep_rva - header_offset_from_ep;
        size_t stub_file_off = 0;
        if (!PE64::rva_to_file_offset(file, stub_rva, stub_file_off)) { std::cerr << "[-] Failed to map stub RVA to file offset\n"; return 1; }
        std::cout << "[*] Stub header RVA = 0x" << std::hex << stub_rva << " => file off 0x" << stub_file_off << std::dec << "\n";

        // Set stub vector size based on version and copy data into buffer.
        if (stub_file_off + sizeof(StubHeader) > file.size()) { std::cerr << "[-] Stub header overruns file\n"; return 1; }
        std::vector<uint8_t> stub_bytes(sizeof(StubHeader));
        memcpy(stub_bytes.data(), file.data() + stub_file_off, stub_bytes.size());

        // Decrypt stub header.
        Steam::Decryption::SteamXOR(stub_bytes);

        auto* header = reinterpret_cast<StubHeader*>(stub_bytes.data());
        std::cout << "[*] Stub signature (raw) = 0x" << std::hex << header->signature << std::dec << "\n";
        if (header->signature != STUB_SIGNATURE) { std::cerr << "[-] Stub signature mismatch\n"; return 1; }
        std::cout << "[*] Stub OK. AppID: " << header->appid << " Flags: 0x" << std::hex << header->flags << std::dec << "\n";
        std::cout << "[*] OEP Va: 0x" << std::hex << header->oep_addr << std::dec << " Code raw size: " << header->code_rawsize << "\n";

        // Check stub header flags and print them to the log window.
        bool NoModuleVerification = (header->flags & STUB_FLAG_NoModuleVerification) != 0;
        std::cout << "[*] NoModuleVerification flag: " << (NoModuleVerification ? "YES" : "NO") << "\n";

        bool NoEncryption = (header->flags & STUB_FLAG_NoEncryption) != 0;
        std::cout << "[*] NoEncryption flag: " << (NoEncryption ? "YES" : "NO") << "\n";

        bool NoOwnershipCheck = (header->flags & STUB_FLAG_NoOwnershipCheck) != 0;
        std::cout << "[*] NoOwnershipCheck flag: " << (NoOwnershipCheck ? "YES" : "NO") << "\n";

        bool NoDebuggerCheck = (header->flags & STUB_FLAG_NoDebuggerCheck) != 0;
        std::cout << "[*] NoDebuggerCheck flag: " << (NoDebuggerCheck ? "YES" : "NO") << "\n";

        bool NoErrorDialog = (header->flags & STUB_FLAG_NoErrorDialog) != 0;
        std::cout << "[*] NoErrorDialog flag: " << (NoErrorDialog ? "YES" : "NO") << "\n";

        // Extract SteamDRMP.dll, if one exists 
        if(UnpackSteamDRMPDLL(header, ep_rva, file) == 1) { return 1; }

        if (!NoEncryption) {
            // locate .text section
            auto dos = reinterpret_cast<const PE64::IMAGE_DOS_HEADER_MIN*>(file.data());
            size_t nt_off = static_cast<size_t>(dos->e_lfanew);
            auto nt = reinterpret_cast<const PE64::IMAGE_NT_HEADERS64_MIN*>(file.data() + nt_off);
            const auto& fh = nt->FileHeader;
            size_t sec_off = nt_off + sizeof(uint32_t) + sizeof(PE64::IMAGE_FILE_HEADER_MIN) + fh.SizeOfOptionalHeader;
            auto sh = reinterpret_cast<const PE64::IMAGE_SECTION_HEADER_MIN*>(file.data() + sec_off);

            const PE64::IMAGE_SECTION_HEADER_MIN* text_sh = nullptr;
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
            Steam::Decryption::AES256_ECB_decrypt(header->aes_iv, 16, header->aes_key);

            std::cout << "[*] Running AES-256 CBC decrypt on code bytes\n";
            size_t decrypt_len = (v_code_bytes.size() / 16) * 16;
            if (decrypt_len == 0) { std::cerr << "[-] Nothing to decrypt\n"; return 1; }

            Steam::Decryption::AES256_CBC_decrypt(v_code_bytes.data(), decrypt_len, header->aes_key, header->aes_iv);

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
            auto dos2 = reinterpret_cast<PE64::IMAGE_DOS_HEADER_MIN*>(file.data());
            size_t nt_off2 = static_cast<size_t>(dos2->e_lfanew);
            auto nt2 = reinterpret_cast<PE64::IMAGE_NT_HEADERS64_MIN*>(file.data() + nt_off2);
            nt2->OptionalHeader.AddressOfEntryPoint = new_ep_rva;
            std::cout << "[*] Updated AddressOfEntryPoint to 0x" << std::hex << new_ep_rva << std::dec << "\n";
        } else {
            std::cout << "[*] Skipping EP update (missing values)\n";
        }

        // Remove .bind section
        {
            auto dos2 = reinterpret_cast<PE64::IMAGE_DOS_HEADER_MIN*>(file.data());
            size_t nt_off2 = static_cast<size_t>(dos2->e_lfanew);
            auto nt2 = reinterpret_cast<PE64::IMAGE_NT_HEADERS64_MIN*>(file.data() + nt_off2);
            auto& fh2 = nt2->FileHeader;

            size_t sec_off2 = nt_off2 + sizeof(uint32_t) + sizeof(PE64::IMAGE_FILE_HEADER_MIN) + fh2.SizeOfOptionalHeader;
            auto sh2 = reinterpret_cast<PE64::IMAGE_SECTION_HEADER_MIN*>(file.data() + sec_off2);

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
            auto dos2 = reinterpret_cast<PE64::IMAGE_DOS_HEADER_MIN*>(file.data());
            size_t nt_off2 = static_cast<size_t>(dos2->e_lfanew);
            auto nt2 = reinterpret_cast<PE64::IMAGE_NT_HEADERS64_MIN*>(file.data() + nt_off2);
            uint32_t numDirs = nt2->OptionalHeader.NumberOfRvaAndSizes;
            if (numDirs <= PE64::IMAGE_DIRECTORY_ENTRY_SECURITY) {
                std::cout << "[*] No certificate directory entry\n";
                // Nothing to clear
            }
            else {
                PE64::IMAGE_DATA_DIRECTORY_MIN &certDir = nt2->OptionalHeader.DataDirectory[PE64::IMAGE_DIRECTORY_ENTRY_SECURITY];
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
            uint32_t newChecksum = PE64::CalculatePEChecksum(file);

            auto dos = reinterpret_cast<PE64::IMAGE_DOS_HEADER_MIN*>(file.data());
            auto nt = reinterpret_cast<PE64::IMAGE_NT_HEADERS64_MIN*>(file.data() + dos->e_lfanew);
            nt->OptionalHeader.CheckSum = newChecksum;

            std::cout << "[*] Updated checksum to 0x" << std::hex << newChecksum << std::dec << "\n";
        } else {
            std::cout << "[*] Keeping old checksum by user request\n";
        }

        return 0;
    }
};

