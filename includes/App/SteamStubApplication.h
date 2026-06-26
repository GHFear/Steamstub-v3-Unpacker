#pragma once
// ------------------------------------------------------------------------- //
//  Self-contained SteamStub v3 unpacker By GHFear @ IllusorySoftware        //
//  Object-oriented application controller                                   //
// ------------------------------------------------------------------------- //

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
#include "BrowserSettings.h"
#include "OutputBuffers.h"
#include "../Global/Global.h"
#include "../Tools/PE/x64/PE64.h"
#include "../Tools/Tools.h"
#include "../SteamStub.x64.v30/Header.h"
#include "../SteamStub.x64.v31/Header.h"

namespace SteamStub
{
    class Application
    {
    public:
        static Application& instance()
        {
            static Application app;
            return app;
        }

        int checkVersionInformation(const uint8_t* ptr, size_t size)
        {
            std::vector<uint8_t> file = copyInput(ptr, size);
            if (file.empty()) {
                std::cerr << "[-] Failed to read input file\n";
                return 1;
            }

            std::cout << "[*] Read file, size = " << file.size() << " bytes\n";

            std::vector<uint8_t> bindBuffer;
            if (!extractBindBuffer(file, bindBuffer)) {
                return 0;
            }

            return detector_.detect(bindBuffer);
        }

        int unpackBuffer(const uint8_t* ptr, size_t size)
        {
            std::vector<uint8_t> file = copyInput(ptr, size);
            outputs_.clear();

            if (file.empty()) {
                std::cerr << "[-] Failed to read input file\n";
                return 1;
            }

            std::cout << "[*] Read file, size = " << file.size() << " bytes\n";

            std::vector<uint8_t> bindBuffer;
            if (!extractBindBuffer(file, bindBuffer)) {
                return 1;
            }

            const SteamStubVersion version = detector_.detect(bindBuffer);
            const int result = unpackByVersion(version, file);
            if (result != 0) {
                std::cerr << "Couldn't unpack steamstub exe. (FAILURE)";
                return 1;
            }

            outputs_.setUnpackedSection(std::move(file));
            return 0;
        }

        uint8_t* unpackedPtr()
        {
            return outputs_.unpackedSectionData();
        }

        size_t unpackedSize() const
        {
            return outputs_.unpackedSectionSize();
        }

        uint8_t* unpackedDRMPPtr()
        {
            return outputs_.unpackedDRMPData();
        }

        size_t unpackedDRMPSize() const
        {
            return outputs_.unpackedDRMPSize();
        }

        OutputBuffers& outputs()
        {
            return outputs_;
        }

    private:
        Application()
            : outputs_(globalOutputBuffers())
        {
        }

        static std::vector<uint8_t> copyInput(const uint8_t* ptr, size_t size)
        {
            if (!ptr || size == 0) {
                return {};
            }

            return std::vector<uint8_t>(ptr, ptr + size);
        }

        static bool extractBindBuffer(std::vector<uint8_t>& file, std::vector<uint8_t>& bindBuffer)
        {
            size_t sectionSize = 0;
            size_t sectionOffset = 0;
            if (!PE64::Image(file).extractBindSection(sectionSize, sectionOffset)) {
                return false;
            }

            bindBuffer.resize(sectionSize);
            std::memcpy(bindBuffer.data(), file.data() + sectionOffset, sectionSize);
            return true;
        }

        int unpackByVersion(SteamStubVersion version, std::vector<uint8_t>& file)
        {
            switch (version) {
                case x64_V30:
                    return SteamStub_x64_v30::UnpackCodeSection(file, outputs_, settings_);
                case x64_V310:
                case x64_V312:
                    return SteamStub_x64_v31::UnpackCodeSection(file, outputs_, settings_);
                default:
                    return 1;
            }
        }

        OutputBuffers& outputs_;
        BrowserSettings settings_;
        SteamStubVersionDetector detector_;
    };
}
