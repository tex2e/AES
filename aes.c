#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hex.h"

static void xor(unsigned char *target, const unsigned char *src, int len)
{
    while (len--) {
        *target++ ^= *src++;
    }
}

static void rotate_word(unsigned char *w)
{
    unsigned char tmp;
    tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

static unsigned char sbox[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
     0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
     0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
     0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
     0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
     0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
     0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
     0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
     0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
     0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
     0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
     0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
     0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
     0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
     0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
     0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
     0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16},
};

static unsigned char inv_sbox[16][16] = {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
     0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
     0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
     0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
     0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
     0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
     0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
     0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
     0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
     0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
     0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
     0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
     0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
     0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
     0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
     0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
     0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
};

static void substitute_word(unsigned char *w)
{
    int i = 0;
    for (i = 0; i < 4; i++) {
        w[i] = sbox[ (w[i] & 0xF0) >> 4 ][ w[i] & 0x0F ];
    }
}

static void compute_key_schedule(const unsigned char *key,
                                 int key_length,
                                 unsigned char w[][4])
{
    // AES 128-bit key schedule computation
    //
    // Initial Key Input     Key Schedule
    // [ 4 bytes ] --------> [ 4 bytes ] ------------------+   bytes 1-4
    //                                                     |
    // [ 4 bytes ] --------> [ 4 bytes ] --------------+   |   bytes 5-8
    //                                                 |   |
    // [ 4 bytes ] --------> [ 4 bytes ] ----------+   |   |   bytes 9-12
    //                                             |   |   V
    // [ 4 bytes ] --------> [ 4 bytes ] ----------|---|->(+)  bytes 13-16
    //                                             |   |   |
    //                            +----------------|---|---+
    //                            V                |   V
    //                       [ 4 bytes ] rot sub --|->(+)      bytes 17-20
    //                                             |   |
    //                            +----------------|---+
    //                            V                V
    //                       [ 4 bytes ] -------->(+)          bytes 21-24
    //                                             |
    //                            +----------------+
    //                            V
    //                       [ 4 bytes ] rot sub               bytes 25-28
    //                            :                                 :
    int i;
    int key_words = key_length >> 2; // AES-128: 4, AES-256: 8
    unsigned char rcon = 0x01;

    // First, copy the key directly into the key schedule
    memcpy(w, key, key_length);
    for (i = key_words; i < 4 * (key_words + 7); i++) {
        memcpy(w[i], w[i-1], 4);
        if (!(i % key_words)) {
            rotate_word(w[i]);
            substitute_word(w[i]);
            if (!(i % 36)) {
                rcon = 0x1b; // modulo
            }
            w[i][0] ^= rcon;
            rcon <<= 1;
        }
        else if ((key_words > 6) && ((i % key_words) == 4)) {
            substitute_word(w[i]);
        }
        w[i][0] ^= w[i - key_words][0];
        w[i][1] ^= w[i - key_words][1];
        w[i][2] ^= w[i - key_words][2];
        w[i][3] ^= w[i - key_words][3];
    }
}

static void add_round_key(unsigned char state[][4],
                          unsigned char w[][4])
{
    //   state           w
    //   0 4 8 c         0 1 2 3
    //   1 5 9 d   XOR   4 5 6 7
    //   2 6 a e         8 9 a b
    //   3 7 b f         c d e f
    int c, r;
    for (c = 0; c < 4; c++) {
        for (r = 0; r < 4; r++) {
            state[r][c] = state[r][c] ^ w[c][r];
        }
    }
}

static void substitute_bytes(unsigned char state[][4])
{
    // s_ij <- sbox(s_ij)
    int c, r;
    for (c = 0; c < 4; c++) {
        for (r = 0; r < 4; r++) {
            state[r][c] = sbox[ (state[r][c] & 0xF0) >> 4 ]
                              [ state[r][c] & 0x0F ];
        }
    }
}

static void inv_substitute_bytes(unsigned char state[][4])
{
    // s_ij <- inv_sbox(s_ij)
    int c, r;
    for (c = 0; c < 4; c++) {
        for (r = 0; r < 4; r++) {
            state[r][c] = inv_sbox[ (state[r][c] & 0xF0) >> 4 ]
                                  [ state[r][c] & 0x0F ];
        }
    }
}

static void shift_rows(unsigned char state[][4])
{
    //   state
    //  |0 4 8 c        |0 4 8 c
    //  |1 5 9 d   ==>   d|1 5 9
    //  |2 6 a e         a e|2 6
    //  |3 7 b f         7 b f|3
    int tmp;
    tmp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tmp;

    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    tmp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = tmp;
}

static void inv_shift_rows(unsigned char state[][4])
{
    //   state
    //  |0 4 8 c        |0 4 8 c
    //   d|1 5 9   ==>  |1 5 9 d
    //   a e|2 6        |2 6 a e
    //   7 b f|3        |3 7 b f
    int tmp;
    tmp = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = state[1][3];
    state[1][3] = tmp;

    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    tmp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tmp;
}

// "left-shift and XOR with 0x1b on overflow" operation
unsigned char xtime(unsigned char x)
{
    // multiply(<<) and subtract(^) modulo x^8 + x^4 + x^3 + x + 1
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

unsigned char dot(unsigned char x, unsigned char y)
{
    // multiply x and y over GF(2^8) with modulo x^8 + x^4 + x^3 + x + 1
    unsigned char mask;
    unsigned char product = 0;

    for (mask = 0x01; mask; mask <<= 1) {
        if (y & mask) {
            product ^= x;
        }
        x = xtime(x);
    }
    return product;
}

static void mix_columns(unsigned char s[][4])
{
    //   | 0 | 4 | 8 | c |           | 0'| 4'| 8'| c'|
    //   | 1 | 5 | 9 | d |           | 1'| 5'| 9'| d'|
    //   | 2 | 6 | a | e |           | 2'| 6'| a'| e'|
    //   | 3 | 7 | b | f |           | 3'| 7'| b'| f'|
    //     |   |   |   |               ^   ^   ^   ^
    //     +---|---|---|---------------+   |   |   |
    //         +---|---|-------------------+   |   |
    //             +---|-----------------------+   |
    //                 +---------------------------+
    //
    //   [ d_0 ]   [ 02 03 01 01 ] [ b_0 ]
    //   [ d_1 ] = [ 01 02 03 01 ] [ b_1 ]
    //   [ d_2 ]   [ 01 01 02 03 ] [ b_2 ]
    //   [ d_3 ]   [ 03 01 01 02 ] [ b_3 ]
    int c;
    unsigned char t[4];

    for (c = 0; c < 4; c++) {
        t[0] = dot(0x02, s[0][c]) ^ dot(0x03, s[1][c]) ^
                         s[2][c]  ^           s[3][c];
        t[1] =           s[0][c]  ^ dot(0x02, s[1][c]) ^
               dot(0x03, s[2][c]) ^           s[3][c];
        t[2] =           s[0][c]  ^           s[1][c]  ^
               dot(0x02, s[2][c]) ^ dot(0x03, s[3][c]);
        t[3] = dot(0x03, s[0][c]) ^           s[1][c]  ^
                         s[2][c]  ^ dot(0x02, s[3][c]);
        s[0][c] = t[0];
        s[1][c] = t[1];
        s[2][c] = t[2];
        s[3][c] = t[3];
    }
}

static void inv_mix_columns(unsigned char s[][4])
{
    //   [ b_0 ]   [ 0e 0b 0d 09 ] [ d_0 ]
    //   [ b_1 ] = [ 09 0e 0b 0d ] [ d_1 ]
    //   [ b_2 ]   [ 0d 09 0e 0b ] [ d_2 ]
    //   [ b_3 ]   [ 0b 0d 09 0e ] [ d_3 ]
    int c;
    unsigned char t[4];

    for (c = 0; c < 4; c++) {
        t[0] = dot(0x0e, s[0][c]) ^ dot(0x0b, s[1][c]) ^
               dot(0x0d, s[2][c]) ^ dot(0x09, s[3][c]);
        t[1] = dot(0x09, s[0][c]) ^ dot(0x0e, s[1][c]) ^
               dot(0x0b, s[2][c]) ^ dot(0x0d, s[3][c]);
        t[2] = dot(0x0d, s[0][c]) ^ dot(0x09, s[1][c]) ^
               dot(0x0e, s[2][c]) ^ dot(0x0b, s[3][c]);
        t[3] = dot(0x0b, s[0][c]) ^ dot(0x0d, s[1][c]) ^
               dot(0x09, s[2][c]) ^ dot(0x0e, s[3][c]);
        s[0][c] = t[0];
        s[1][c] = t[1];
        s[2][c] = t[2];
        s[3][c] = t[3];
    }
}

void aes_block_encrypt(const unsigned char *input_block,
                       unsigned char *output_block,
                       const unsigned char *key,
                       int key_size)
{
    int r, c;
    int round;
    int nr;
    unsigned char state[4][4];
    unsigned char w[60][4];

    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            state[r][c] = input_block[r + 4*c];
        }
    }
    // rounds = key size in 4-byte words + 6
    nr = (key_size >> 2) + 6;

    compute_key_schedule(key, key_size, w);

    add_round_key(state, &w[0]);
    for (round = 0; round < nr; round++) {
        substitute_bytes(state);
        shift_rows(state);
        if (round < nr - 1) {
            mix_columns(state);
        }
        add_round_key(state, &w[ (round+1)*4 ]);
    }

    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            output_block[r + 4*c] = state[r][c];
        }
    }
}

void aes_block_decrypt(const unsigned char *input_block,
                       unsigned char *output_block,
                       const unsigned char *key,
                       int key_size)
{
    int r, c;
    int round;
    int nr;
    unsigned char state[4][4];
    unsigned char w[60][4];

    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            state[r][c] = input_block[r + 4*c];
        }
    }
    // rounds = key size in 4-byte words + 6
    nr = (key_size >> 2) + 6;

    compute_key_schedule(key, key_size, w);

    add_round_key(state, &w[nr * 4]);
    for (round = nr; round > 0; round--) {
        inv_shift_rows(state);
        inv_substitute_bytes(state);
        add_round_key(state, &w[ (round-1)*4 ]);
        if (round > 1) {
            inv_mix_columns(state);
        }
    }

    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            output_block[r + 4*c] = state[r][c];
        }
    }
}


#define AES_BLOCK_SIZE 16

static void aes_encrypt(const unsigned char *input,
                        int input_len,
                        unsigned char *output,
                        const unsigned char *iv,
                        const unsigned char *key,
                        int key_length)
{
    unsigned char input_block[AES_BLOCK_SIZE];

    while (input_len >= AES_BLOCK_SIZE) {
        memcpy(input_block, input, AES_BLOCK_SIZE);
        xor(input_block, iv, AES_BLOCK_SIZE); // implement CBC
        aes_block_encrypt(input_block, output, key, key_length);
        memcpy((void *)iv, (void *)input, AES_BLOCK_SIZE); // CBC
        input += AES_BLOCK_SIZE;
        output += AES_BLOCK_SIZE;
        input_len -= AES_BLOCK_SIZE;
    }
}

static void aes_decrypt(const unsigned char *input,
                        int input_len,
                        unsigned char *output,
                        const unsigned char *iv,
                        const unsigned char *key,
                        int key_length)
{
    while (input_len >= AES_BLOCK_SIZE) {
        aes_block_decrypt(input, output, key, key_length);
        xor(output, iv, AES_BLOCK_SIZE);
        memcpy((void *)iv, (void *)output, AES_BLOCK_SIZE); // CBC
        input += AES_BLOCK_SIZE;
        output += AES_BLOCK_SIZE;
        input_len -= AES_BLOCK_SIZE;
    }
}

void aes_128_encrypt(const unsigned char *plaintext,
                     const int plaintext_len,
                     unsigned char ciphertext[],
                     void *iv,
                     const unsigned char *key)
{
    aes_encrypt(plaintext, plaintext_len, ciphertext,
                (const unsigned char *)iv, key, 16);
}

void aes_256_encrypt(const unsigned char *plaintext,
                     const int plaintext_len,
                     unsigned char ciphertext[],
                     void *iv,
                     const unsigned char *key)
{
    aes_encrypt(plaintext, plaintext_len, ciphertext,
                (const unsigned char *)iv, key, 32);
}

void aes_128_decrypt(const unsigned char *ciphertext,
                     const int ciphertext_len,
                     unsigned char plaintext[],
                     void *iv,
                     const unsigned char *key)
{
    aes_decrypt(ciphertext, ciphertext_len, plaintext,
                (const unsigned char *)iv, key, 16);
}

void aes_256_decrypt(const unsigned char *ciphertext,
                     const int ciphertext_len,
                     unsigned char plaintext[],
                     void *iv,
                     const unsigned char *key)
{
    aes_decrypt(ciphertext, ciphertext_len, plaintext,
                (const unsigned char *)iv, key, 32);
}


// Multiply X by Y in a GF(128) field and return the result in Z.
static void gf_multiply(const unsigned char *X,
                        const unsigned char *Y,
                        unsigned char *Z)
{
    unsigned char V[AES_BLOCK_SIZE];
    unsigned char R[AES_BLOCK_SIZE];
    unsigned char mask;
    int i, j;
    int lsb;

    memset(Z, '\0', AES_BLOCK_SIZE);
    memset(R, '\0', AES_BLOCK_SIZE);
    R[0] = 0xE1; // 0b11100001 == x^128 + x^7 + x^2 + x + 1
    memcpy(V, X, AES_BLOCK_SIZE);
    for (i = 0; i < 16; i++) {
        for (mask = 0x80; mask; mask >>= 1) {
            if (Y[i] & mask) {
                xor(Z, V, AES_BLOCK_SIZE);
            }

            // multiply(<<) and subtract(^) modulo x^128 + x^7 + x^2 + x + 1
            lsb = (V[AES_BLOCK_SIZE-1] & 0x01);
            // multiply
            for (j = AES_BLOCK_SIZE - 1; j; j--) {
                V[j] = (V[j] >> 1) | ((V[j-1] & 0x01) << 7);
            }
            V[0] >>= 1;
            // subtract
            if (lsb) {
                xor(V, R, AES_BLOCK_SIZE);
            }
        }
    }
}
