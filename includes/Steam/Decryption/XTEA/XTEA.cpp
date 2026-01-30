// ------------------------------------------------------------------------- //
//  Self-contained SteamStub v3 unpacker By GHFear @ IllusorySoftware        //
//  Compatible with Emscripten (drop the emsdk folder next to this file and  //
//  compile with the included compile script for linux)                      //
// ------------------------------------------------------------------------- //
//  Lots of credit to Cyanic (aka Golem_x86), atom0s and illnyang for prior  //
//  research on steamstub drm.                                               //
//  Without y'all, this wouldn't be possible.                                //
// ------------------------------------------------------------------------- //
#include "../Decryption.h"

void Steam::Decryption::XTEAPass2(uint32_t res[2], const uint32_t* keys, uint32_t blockLo, uint32_t blockHi, uint32_t n = 32)
{
    constexpr uint32_t delta = 0x9E3779B9;
    constexpr uint32_t mask  = 0xFFFFFFFF;

    uint32_t sum = (delta * n) & mask;

    for (uint32_t x = 0; x < n; ++x)
    {
        blockHi = (blockHi - (((blockLo << 4 ^ blockLo >> 5) + blockLo) ^ (sum + keys[(sum >> 11) & 3]))) & mask;
        sum = (sum - delta) & mask;
        blockLo = (blockLo - (((blockHi << 4 ^ blockHi >> 5) + blockHi) ^ (sum + keys[sum & 3]))) & mask;
    }

    res[0] = blockLo;
    res[1] = blockHi;
}

void Steam::Decryption::XTEAPass1(std::vector<uint8_t>& data, const uint32_t* keys)
{
    std::cout << "[*] Decrypting SteamDRMP.dll (XTEA Decryption)\n";
    uint32_t chainLo = 0x55555555;
    uint32_t chainHi = 0x55555555;

    const size_t size = data.size();

    for (size_t x = 0; x < size; x += 8)
    {
        uint32_t blockLo, blockHi;

        std::memcpy(&blockLo, &data[x + 0], sizeof(uint32_t));
        std::memcpy(&blockHi, &data[x + 4], sizeof(uint32_t));

        uint32_t res[2];
        XTEAPass2(res, keys, blockLo, blockHi);

        uint32_t out1 = res[0] ^ chainLo;
        uint32_t out2 = res[1] ^ chainHi;

        std::memcpy(&data[x + 0], &out1, sizeof(uint32_t));
        std::memcpy(&data[x + 4], &out2, sizeof(uint32_t));

        chainLo = blockLo;
        chainHi = blockHi;
    }
}