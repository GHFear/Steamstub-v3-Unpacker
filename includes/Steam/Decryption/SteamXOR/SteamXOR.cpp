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

void* Steam::Decryption::SteamXOR(std::vector<uint8_t>& stub_bytes) {
    std::cout << "[*] Rolling XOR unwrap of stub header\n";
    uint32_t key = *reinterpret_cast<uint32_t*>(stub_bytes.data());
    uint8_t* p = stub_bytes.data() + sizeof(uint32_t);
    uint8_t* endp = stub_bytes.data() + stub_bytes.size();
    while (p < endp) {
        uint32_t val = *reinterpret_cast<uint32_t*>(p);
        *reinterpret_cast<uint32_t*>(p) = val ^ key;
        key = val;
        p += sizeof(uint32_t);
    }
    return 0;
}