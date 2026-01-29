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

// Credit to illnyang | https://github.com/illnyang/steamstub_unpack/blob/trunk/src/main.cc
#define STUB_FLAG_NoModuleVerification 0x02
#define STUB_FLAG_NoEncryption 0x04
#define STUB_FLAG_NoOwnershipCheck 0x10
#define STUB_FLAG_NoDebuggerCheck 0x20
#define STUB_FLAG_NoErrorDialog 0x40
// ----------------------------------------------------------------------------------------

#define STUB_SIGNATURE 0xC0DEC0DFu
