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

#include "../App/BrowserSettings.h"

// These wrappers keep the original exported helper names available while the
// implementation now lives in the BrowserSettings class.
EMSCRIPTEN_KEEPALIVE
inline bool isUpdateChecksumChecked()
{
    return SteamStub::BrowserSettings().updateChecksum();
}

EMSCRIPTEN_KEEPALIVE
inline bool isRemoveCertChecked()
{
    return SteamStub::BrowserSettings().removeCertificate();
}

EMSCRIPTEN_KEEPALIVE
inline bool isKeepBindChecked()
{
    return SteamStub::BrowserSettings().keepBindSection();
}

EMSCRIPTEN_KEEPALIVE
inline bool isDumpDRMPChecked()
{
    return SteamStub::BrowserSettings().dumpDRMP();
}
