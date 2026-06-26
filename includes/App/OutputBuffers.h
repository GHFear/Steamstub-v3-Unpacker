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

#include <cstddef>
#include <cstdint>
#include <vector>

namespace SteamStub
{
    class OutputBuffers
    {
    public:
        void clear()
        {
            unpackedSection_.clear();
            unpackedDRMP_.clear();
            unpackedPayload_.clear();
        }

        void setUnpackedSection(std::vector<uint8_t>&& data)
        {
            unpackedSection_ = std::move(data);
        }

        void setUnpackedDRMP(std::vector<uint8_t>&& data)
        {
            unpackedDRMP_ = std::move(data);
        }

        void setUnpackedPayload(std::vector<uint8_t>&& data)
        {
            unpackedPayload_ = std::move(data);
        }

        std::vector<uint8_t>& unpackedSection() { return unpackedSection_; }
        std::vector<uint8_t>& unpackedDRMP() { return unpackedDRMP_; }
        std::vector<uint8_t>& unpackedPayload() { return unpackedPayload_; }

        const std::vector<uint8_t>& unpackedSection() const { return unpackedSection_; }
        const std::vector<uint8_t>& unpackedDRMP() const { return unpackedDRMP_; }
        const std::vector<uint8_t>& unpackedPayload() const { return unpackedPayload_; }

        uint8_t* unpackedSectionData()
        {
            return unpackedSection_.empty() ? nullptr : unpackedSection_.data();
        }

        uint8_t* unpackedDRMPData()
        {
            return unpackedDRMP_.empty() ? nullptr : unpackedDRMP_.data();
        }

        size_t unpackedSectionSize() const { return unpackedSection_.size(); }
        size_t unpackedDRMPSize() const { return unpackedDRMP_.size(); }

    private:
        std::vector<uint8_t> unpackedSection_;
        std::vector<uint8_t> unpackedDRMP_;
        std::vector<uint8_t> unpackedPayload_;
    };
}
