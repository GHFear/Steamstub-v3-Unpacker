// ------------------------------------------------------------------------- //
//  Self-contained SteamStub v3 unpacker By GHFear @ IllusorySoftware        //
//  Version 0.1.9                                                            //
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
#include <emscripten.h>
#include <emscripten/html5.h>
#include <emscripten/val.h>
#include "includes/Global/Global.h"
#include "includes/Steam/Decryption/Decryption.h"
#include "includes/Tools/PE/x64/PE64.h"
#include "includes/Tools/Tools.h"
#include "includes/Settings/Checkboxes.h"
#include "includes/SteamStub.x64.v30/Header.h"
#include "includes/SteamStub.x64.v31/Header.h"

// I might want to compile the application to an executable at some point. Keep main.
int main(int argc, char** argv) {
    return 0;
}

extern "C" {
    EMSCRIPTEN_KEEPALIVE // C++ function that can check the SteamStub version.
    int check_version_information(uint8_t* ptr, size_t size) {
        // Copy file buffer into vector
        std::vector<uint8_t> file(ptr, ptr + size);

        if (file.empty()) { std::cerr << "[-] Failed to read input file\n"; return 1; }
        std::cout << "[*] Read file, size = " << file.size() << " bytes\n";

        // Extract .bind section into its own buffer for faster scanning and less false positives.
        size_t section_size = -1;
        size_t section_offset = -1;
        if (!PE64::extract_bind(file, section_size, section_offset)) { return 0; }
        std::vector<uint8_t> bind_buffer(section_size);
        std::memcpy(bind_buffer.data(), file.data() + section_offset, section_size);
        return get_steamstub_version(bind_buffer);
    }
    
    // Called from JS with pointer to file buffer
    EMSCRIPTEN_KEEPALIVE
    int unpack_buffer(uint8_t* ptr, size_t size) {
        // Copy file buffer into vector
        std::vector<uint8_t> file(ptr, ptr + size);

        // Clear output buffers.
        unpacked_buffer.clear();
        unpackedDRMP_buffer.clear();

        if (file.empty()) { std::cerr << "[-] Failed to read input file\n"; return 1; }
        std::cout << "[*] Read file, size = " << file.size() << " bytes\n";

        // Extract .bind section into its own buffer for faster scanning and less false positives.
        size_t section_size = -1;
        size_t section_offset = -1;
        if (!PE64::extract_bind(file, section_size, section_offset)) { return 1; }
        std::vector<uint8_t> bind_buffer(section_size);
        std::memcpy(bind_buffer.data(), file.data() + section_offset, section_size);

        SteamStubVersion steamstub_version = get_steamstub_version(bind_buffer);

        // Run unpacker based on SteamStub version.
        int result = 1;
        if (steamstub_version == x64_V30)
        {
            result = SteamStub_x64_v30::UnpackStub(file);
        }
        else if (steamstub_version == x64_V310 || steamstub_version == x64_V312)
        {
            result = SteamStub_x64_v31::UnpackStub(file);
        }
        else
        {
            return 1;
        }
        
        if (result != 0) { std::cerr << "Couldn't unpack steamstub exe. (FAILURE)"; return 1; }
        
        // For final, move unpacked file to unpacked_buffer.
        unpacked_buffer = std::move(file);

        return 0;
    }

    // Functions for JS to fetch unpacked buffer pointer + size
    EMSCRIPTEN_KEEPALIVE
    uint8_t* get_unpacked_ptr() { return unpacked_buffer.data(); }

    EMSCRIPTEN_KEEPALIVE
    size_t get_unpacked_size() { return unpacked_buffer.size(); }

    // Functions for JS to fetch unpacked DRMP buffer pointer + size
    EMSCRIPTEN_KEEPALIVE
    uint8_t* get_unpackedDRMP_ptr() { return unpackedDRMP_buffer.data(); }

    EMSCRIPTEN_KEEPALIVE
    size_t get_unpackedDRMP_size() { return unpackedDRMP_buffer.size(); }

    // Example JS save call
    EM_JS(void, open_file_js, (), {
        const input = document.createElement('input');
        input.type = 'file';
        input.onchange = async(e) =>
        {
            const file = e.target.files && e.target.files[0];
            console.log(file.name);
            await loadExecutableBuffer(file);
        };
    });

    EMSCRIPTEN_KEEPALIVE
    void open_file() {
        open_file_js();
    }

}

