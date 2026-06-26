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

#include <cstddef>
#include <cstdint>
#include <emscripten.h>
#include "includes/App/SteamStubApplication.h"

// I might want to compile the application to an executable at some point. Keep main.
int main(int argc, char** argv)
{
    return 0;
}

extern "C" {
    EMSCRIPTEN_KEEPALIVE
    int check_version_information(uint8_t* ptr, size_t size)
    {
        return SteamStub::Application::instance().checkVersionInformation(ptr, size);
    }

    EMSCRIPTEN_KEEPALIVE
    int unpack_buffer(uint8_t* ptr, size_t size)
    {
        return SteamStub::Application::instance().unpackBuffer(ptr, size);
    }

    EMSCRIPTEN_KEEPALIVE
    uint8_t* get_unpacked_ptr()
    {
        return SteamStub::Application::instance().unpackedPtr();
    }

    EMSCRIPTEN_KEEPALIVE
    size_t get_unpacked_size()
    {
        return SteamStub::Application::instance().unpackedSize();
    }

    EMSCRIPTEN_KEEPALIVE
    uint8_t* get_unpackedDRMP_ptr()
    {
        return SteamStub::Application::instance().unpackedDRMPPtr();
    }

    EMSCRIPTEN_KEEPALIVE
    size_t get_unpackedDRMP_size()
    {
        return SteamStub::Application::instance().unpackedDRMPSize();
    }

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
    void open_file()
    {
        open_file_js();
    }
}
