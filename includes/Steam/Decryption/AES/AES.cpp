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

namespace Steam 
{
    uint8_t Steam::Decryption::multiply(uint8_t a, uint8_t b) {
        uint8_t result = 0;
        uint8_t temp = a;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) result ^= temp;
            uint8_t hi_bit = temp & 0x80;
            temp <<= 1;
            if (hi_bit) temp ^= 0x1B;
            b >>= 1;
        }
        return result;
    }

    void Steam::Decryption::KeyExpansion256(const uint8_t key[32], uint8_t roundKeys[240]) {
        memcpy(roundKeys, key, 32);
        int bytesGenerated = 32;
        int rconIteration = 0;
        uint8_t temp[4];

        while (bytesGenerated < 240) {
            for (int i = 0; i < 4; ++i)
                temp[i] = roundKeys[bytesGenerated - 4 + i];

            if (bytesGenerated % 32 == 0) {
                uint8_t t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                temp[0] = sbox[temp[0]];
                temp[1] = sbox[temp[1]];
                temp[2] = sbox[temp[2]];
                temp[3] = sbox[temp[3]];

                temp[0] ^= Rcon[rconIteration++];
            } else if (bytesGenerated % 32 == 16) {
                temp[0] = sbox[temp[0]];
                temp[1] = sbox[temp[1]];
                temp[2] = sbox[temp[2]];
                temp[3] = sbox[temp[3]];
            }

            for (int i = 0; i < 4; ++i) {
                roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 32] ^ temp[i];
                bytesGenerated++;
            }
        }
    }

    void Steam::Decryption::AddRoundKey(uint8_t state[16], const uint8_t* roundKey) {
        for (int i = 0; i < 16; ++i) state[i] ^= roundKey[i];
    }

    void Steam::Decryption::InvSubBytes(uint8_t state[16]) {
        for (int i = 0; i < 16; ++i) state[i] = inv_sbox[state[i]];
    }

    void Steam::Decryption::InvShiftRows(uint8_t state[16]) {
        uint8_t tmp[16];
        // row 0
        tmp[0] = state[0];
        tmp[4] = state[4];
        tmp[8] = state[8];
        tmp[12] = state[12];
        // row 1
        tmp[1]  = state[13];
        tmp[5]  = state[1];
        tmp[9]  = state[5];
        tmp[13] = state[9];
        // row 2
        tmp[2] = state[10];
        tmp[6] = state[14];
        tmp[10] = state[2];
        tmp[14] = state[6];
        // row 3
        tmp[3]  = state[7];
        tmp[7]  = state[11];
        tmp[11] = state[15];
        tmp[15] = state[3];
        memcpy(state, tmp, 16);
    }

    void Steam::Decryption::InvMixColumns(uint8_t state[16]) {
        for (int i = 0; i < 4; ++i) {
            int col = 4 * i;
            uint8_t a0 = state[col + 0];
            uint8_t a1 = state[col + 1];
            uint8_t a2 = state[col + 2];
            uint8_t a3 = state[col + 3];

            uint8_t r0 = (uint8_t)(multiply(a0, 0x0e) ^ multiply(a1, 0x0b) ^ multiply(a2, 0x0d) ^ multiply(a3, 0x09));
            uint8_t r1 = (uint8_t)(multiply(a0, 0x09) ^ multiply(a1, 0x0e) ^ multiply(a2, 0x0b) ^ multiply(a3, 0x0d));
            uint8_t r2 = (uint8_t)(multiply(a0, 0x0d) ^ multiply(a1, 0x09) ^ multiply(a2, 0x0e) ^ multiply(a3, 0x0b));
            uint8_t r3 = (uint8_t)(multiply(a0, 0x0b) ^ multiply(a1, 0x0d) ^ multiply(a2, 0x09) ^ multiply(a3, 0x0e));

            state[col + 0] = r0;
            state[col + 1] = r1;
            state[col + 2] = r2;
            state[col + 3] = r3;
        }
    }

    void Steam::Decryption::AES256_DecryptBlock(uint8_t state[16], const uint8_t roundKeys[240]) {
        AddRoundKey(state, roundKeys + 224);
        for (int round = 13; round >= 1; --round) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, roundKeys + round * 16);
            InvMixColumns(state);
        }
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + 0);
    }

    void Steam::Decryption::AES256_ECB_decrypt(uint8_t* buf, size_t len, const uint8_t key[32]) {
        if (len % 16 != 0) return;
        uint8_t roundKeys[240];
        KeyExpansion256(key, roundKeys);
        uint8_t block[16];
        for (size_t off = 0; off < len; off += 16) {
            memcpy(block, buf + off, 16);
            AES256_DecryptBlock(block, roundKeys);
            memcpy(buf + off, block, 16);
        }
    }

    void Steam::Decryption::AES256_CBC_decrypt(uint8_t* buf, size_t len, const uint8_t key[32], uint8_t iv[16]) {
        if (len % 16 != 0) return;
        uint8_t roundKeys[240];
        KeyExpansion256(key, roundKeys);

        uint8_t prev[16];
        memcpy(prev, iv, 16);

        uint8_t block[16];
        for (size_t off = 0; off < len; off += 16) {
            memcpy(block, buf + off, 16);
            uint8_t cipher_block[16];
            memcpy(cipher_block, block, 16);

            AES256_DecryptBlock(block, roundKeys);
            for (int i = 0; i < 16; ++i) block[i] ^= prev[i];
            memcpy(buf + off, block, 16);
            memcpy(prev, cipher_block, 16);
        }
        memcpy(iv, prev, 16);
    }
};

