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

#define STUB_FLAG_None 0x00
#define STUB_FLAG_UseValidation 0x01
#define STUB_FLAG_UseWinVerifyTrustValidation 0x02
#define STUB_FLAG_UseEncodedCodeSection 0x04
#define STUB_FLAG_UseThreadCheckValidation 0x08
#define STUB_FLAG_UseMemoryMappedValidation 0x10
#define STUB_SIGNATURE 0xC0DEC0DFu
