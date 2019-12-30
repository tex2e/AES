#ifndef AES_H
#define AES_H

// https://github.com/yhyuan/Implementing-SSL-TLS-Using-Cryptography-and-PKI/blob/master/after/ch02
// https://github.com/yhyuan/Implementing-SSL-TLS-Using-Cryptography-and-PKI/tree/master/after/ch09

void aes_block_encrypt(const unsigned char *input_block,
                       unsigned char *output_block,
                       const unsigned char *key,
                       int key_size);

void aes_block_decrypt(const unsigned char *input_block,
                       unsigned char *output_block,
                       const unsigned char *key,
                       int key_size);

void aes_128_encrypt(const unsigned char *plaintext,
                     const int plaintext_len,
                     unsigned char ciphertext[],
                     unsigned char *iv,
                     const unsigned char *key);

void aes_128_decrypt(const unsigned char *ciphertext,
                     const int ciphertext_len,
                     unsigned char plaintext[],
                     unsigned char *iv,
                     const unsigned char *key);

void aes_256_encrypt(const unsigned char *plaintext,
                     const int plaintext_len,
                     unsigned char ciphertext[],
                     unsigned char *iv,
                     const unsigned char *key);

void aes_256_decrypt(const unsigned char *ciphertext,
                     const int ciphertext_len,
                     unsigned char plaintext[],
                     unsigned char *iv,
                     const unsigned char *key);

int aes_gcm_encrypt(const unsigned char *input,
                    int intput_len,
                    const unsigned char *addldata,
                    const int addldata_len,
                    unsigned char *output,
                    void *iv,
                    const unsigned char *key);

#endif
