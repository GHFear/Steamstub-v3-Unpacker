#pragma once
// ------------------------------------------------------------------------- //
//  Self-contained SteamStub v3 unpacker By GHFear @ IllusorySoftware        //
//  Backwards-compatible access to object-oriented output buffers            //
// ------------------------------------------------------------------------- //

#include <cstdint>
#include <vector>
#include "../App/OutputBuffers.h"

namespace SteamStub
{
    inline OutputBuffers& globalOutputBuffers()
    {
        static OutputBuffers buffers;
        return buffers;
    }
}

// Backwards-compatible accessors for old code. New code should prefer
// SteamStub::OutputBuffers / SteamStub::Application instead of these aliases.
inline std::vector<uint8_t>& unpacked_section_buffer = SteamStub::globalOutputBuffers().unpackedSection();
inline std::vector<uint8_t>& unpacked_drmp_buffer = SteamStub::globalOutputBuffers().unpackedDRMP();
inline std::vector<uint8_t>& unpacked_payload_buffer = SteamStub::globalOutputBuffers().unpackedPayload();
