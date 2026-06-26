#pragma once
// ------------------------------------------------------------------------- //
//  Self-contained SteamStub v3 unpacker By GHFear @ IllusorySoftware        //
//  Object-oriented browser/settings access                                  //
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
