#pragma once
// ------------------------------------------------------------------------- //
//  Self-contained SteamStub v3 unpacker By GHFear @ IllusorySoftware        //
//  Backwards-compatible checkbox helpers                                    //
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
