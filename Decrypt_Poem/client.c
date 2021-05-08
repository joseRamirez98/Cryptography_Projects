#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/* Call before any other server functions. Initializes encryption. */
void server_init();

/* Call after all other server functions. Frees resources. */
void server_close();

/* Writes 16 bytes to buf which will be used for this message's IV */
void server_get_cbc_iv(void *buf);

/* Writes 32 bytes to buf which will be used for this message's AES-256 key */
void server_get_key(void *buf);

/* Returns non-zero if no more data remains and zero if more data remains */
int server_done();

/* Receive next chunk of the ciphertext. Return value is 1 to 256 and is the */
/* number of bytes written to buf. It is an error to call this function when */
/* server_done() is non-zero (ie, true). */
int server_next_chunk(void *buf);


int main() {
    int bytes_encrypted;
    int bytes_decrypted; 
    int pt_bytes_written;
    unsigned char decrypted_text[256];  // will store the decrypted poem
    unsigned char encrypted_text[256];

    unsigned char key[32];         // will store the key used for encryption
    unsigned char iv[16];          // will store the iv used for encryption

    server_init();
    server_get_cbc_iv(iv);
    server_get_key(key);
    
    // create a context cipher for the decryption
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    while(server_done() == 0){
        bytes_encrypted = server_next_chunk(encrypted_text);
        EVP_DecryptUpdate(ctx, decrypted_text, &bytes_decrypted, encrypted_text, bytes_encrypted);
        pt_bytes_written = pt_bytes_written + bytes_decrypted;
        decrypted_text[bytes_decrypted] = '\0';

        // check OpenSLL buffer for unwritten data
        int extra_bytes_written;
        EVP_DecryptFinal_ex(ctx, decrypted_text + bytes_decrypted, &extra_bytes_written);
        if(extra_bytes_written != 0) {
            decrypted_text[bytes_decrypted+extra_bytes_written] = '\0';
            pt_bytes_written = pt_bytes_written + extra_bytes_written;
        }

        // print the chunk of decrypted data
        printf("%s", decrypted_text);
    }

    // close both the cipher contexts
    EVP_CIPHER_CTX_free(ctx);
    server_close();
    return 0;
}
