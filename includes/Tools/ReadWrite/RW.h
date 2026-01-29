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
#include <fstream>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream> 

namespace VectorRW 
{
    // Read from vector buffer with offset. (u8)
    uint8_t read_u8(const std::vector<uint8_t>& buffer, size_t offset)
    {
        if (offset + 1 > buffer.size())
            throw std::out_of_range("Buffer too small");

        uint8_t value;
        std::memcpy(&value, buffer.data() + offset, 1);
        return value;
    }

    // Read from vector buffer with offset. (u16)
    uint16_t read_u16_le(const std::vector<uint8_t>& buffer, size_t offset)
    {
        if (offset + 2 > buffer.size())
            throw std::out_of_range("Buffer too small");

        uint16_t value;
        std::memcpy(&value, buffer.data() + offset, 2);
        return value;
    }

    // Read from vector buffer with offset. (u32)
    uint32_t read_u32_le(const std::vector<uint8_t>& buffer, size_t offset)
    {
        if (offset + 4 > buffer.size())
            throw std::out_of_range("Buffer too small");

        uint32_t value;
        std::memcpy(&value, buffer.data() + offset, 4);
        return value;
    }

    // Read from vector buffer with offset. (u64)
    uint64_t read_u64_le(const std::vector<uint8_t>& buffer, size_t offset)
    {
        if (offset + 8 > buffer.size())
            throw std::out_of_range("Buffer too small");

        uint64_t value;
        std::memcpy(&value, buffer.data() + offset, 8);
        return value;
    }

    // Read from vector buffer with offset. (i8)
    int8_t read_i8(const std::vector<uint8_t>& buffer, size_t offset)
    {
        if (offset + 1 > buffer.size())
            throw std::out_of_range("Buffer too small");

        int8_t value;
        std::memcpy(&value, buffer.data() + offset, 1);
        return value;
    }

    // Read from vector buffer with offset. (i16)
    int16_t read_i16_le(const std::vector<uint8_t>& buffer, size_t offset)
    {
        if (offset + 2 > buffer.size())
            throw std::out_of_range("Buffer too small");

        int16_t value;
        std::memcpy(&value, buffer.data() + offset, 2);
        return value;
    }

    // Read from vector buffer with offset. (i32)
    int32_t read_i32_le(const std::vector<uint8_t>& buffer, size_t offset)
    {
        if (offset + 4 > buffer.size())
            throw std::out_of_range("Buffer too small");

        int32_t value;
        std::memcpy(&value, buffer.data() + offset, 4);
        return value;
    }

    // Read from vector buffer with offset. (i64)
    int64_t read_i64_le(const std::vector<uint8_t>& buffer, size_t offset)
    {
        if (offset + 8 > buffer.size())
            throw std::out_of_range("Buffer too small");

        int64_t value;
        std::memcpy(&value, buffer.data() + offset, 8);
        return value;
    }
};