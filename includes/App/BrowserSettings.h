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

#include <string>
#include <emscripten.h>
#include <emscripten/val.h>

namespace SteamStub
{
    class BrowserSettings
    {
    public:
        bool updateChecksum() const { return checked("updateChecksum"); }
        bool removeCertificate() const { return checked("removeCert"); }
        bool keepBindSection() const { return checked("keepBind"); }
        bool dumpDRMP() const { return checked("dumpDRMP"); }

    private:
        static bool checked(const std::string& elementId)
        {
            emscripten::val document = emscripten::val::global("document");
            emscripten::val checkbox = document.call<emscripten::val>("getElementById", elementId);
            return checkbox["checked"].as<bool>();
        }
    };
}
