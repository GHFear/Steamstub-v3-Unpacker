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
EMSCRIPTEN_KEEPALIVE
bool isUpdateChecksumChecked() {
    emscripten::val document = emscripten::val::global("document");
    emscripten::val checkbox = document.call<emscripten::val>("getElementById", std::string("updateChecksum"));
    return checkbox["checked"].as<bool>();
}

EMSCRIPTEN_KEEPALIVE
bool isRemoveCertChecked() {
    emscripten::val document = emscripten::val::global("document");
    emscripten::val checkbox = document.call<emscripten::val>("getElementById", std::string("removeCert"));
    return checkbox["checked"].as<bool>();
}

EMSCRIPTEN_KEEPALIVE
bool isKeepBindChecked() {
    emscripten::val document = emscripten::val::global("document");
    emscripten::val checkbox = document.call<emscripten::val>("getElementById", std::string("keepBind"));
    return checkbox["checked"].as<bool>();
}