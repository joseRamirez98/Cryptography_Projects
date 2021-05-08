/* Spring 2021 CSC 152 - Ted Krovetz - pseudo server for decryption exercise */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

static EVP_CIPHER_CTX *ctx;      /* encryption context */
static unsigned char iv[16];     /* random initialization vector */
static unsigned char key[32];    /* random AES-256 key */
static int data_len;             /* plaintext (poem) bytelength */
static int data_read;            /* bytes passed to EVP_EncryptUpdate so far */

/* Plaintext to be encrypted and sent */
static const unsigned char poem[] =
    "Jabberwocky\n"
    "By Lewis Carroll\n"
    "\n"
    "\'Twas brillig, and the slithy toves\n"
    "      Did gyre and gimble in the wabe:\n"
    "All mimsy were the borogoves,\n"
    "      And the mome raths outgrabe.\n"
    "\n"
    "\"Beware the Jabberwock, my son!\n"
    "      The jaws that bite, the claws that catch!\n"
    "Beware the Jubjub bird, and shun\n"
    "      The frumious Bandersnatch!\"\n"
    "\n"
    "He took his vorpal sword in hand;\n"
    "      Long time the manxome foe he sought-\n"
    "So rested he by the Tumtum tree\n"
    "      And stood awhile in thought.\n"
    "\n"
    "And, as in uffish thought he stood,\n"
    "      The Jabberwock, with eyes of flame,\n"
    "Came whiffling through the tulgey wood,\n"
    "      And burbled as it came!\n"
    "\n"
    "One, two! One, two! And through and through\n"
    "      The vorpal blade went snicker-snack!\n"
    "He left it dead, and with its head\n"
    "      He went galumphing back.\n"
    "\n"
    "\"And hast thou slain the Jabberwock?\n"
    "      Come to my arms, my beamish boy!\n"
    "O frabjous day! Callooh! Callay!\"\n"
    "      He chortled in his joy.\n"
    "\n"
    "\'Twas brillig, and the slithy toves\n"
    "      Did gyre and gimble in the wabe:\n"
    "All mimsy were the borogoves,\n"
    "      And the mome raths outgrabe.\n";

/* Call before any other server functions. Initializes encryption. */
void server_init() {
    FILE *f = fopen("/dev/urandom", "rb"); /* Good random source */
    fread(iv, 1, 16, f);                   /* 16 byte random iv  */
    fread(key, 1, 32, f);                  /* 32 byte random key */
    fclose(f);                             /* Done getting good random values */
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    data_len = sizeof(poem);   /* sizeof works on statically-allocated arrays */
    data_read = 0;                         /* How much poem encrypted so far  */
}

/* Call after all other server functions. Frees resources. */
void server_close() {
    EVP_CIPHER_CTX_free(ctx);
}

/* Writes 16 bytes to buf which will be used for this message's IV */
void server_get_cbc_iv(void *buf) {
    memcpy(buf, iv, 16);
}

/* Writes 32 bytes to buf which will be used for this message's AES-256 key */
void server_get_key(void *buf) {
    memcpy(buf, key, 32);
}

/* Returns non-zero if no more data remains and zero if more data remains */
int server_done() {
    return data_read == data_len;
}

/* Receive next chunk of the ciphertext. Return value is 1 to 256 and is the */
/* number of bytes written to buf. It is an error to call this function when */
/* server_done() is non-zero (ie, true). */
int server_next_chunk(void *buf) {
    int bytes_written, bytes_to_read;
    bytes_to_read = rand() % (data_len-data_read) + 1;  /* 1..bytes remaining */
    if (bytes_to_read > 256-32) /* 32 bytes in case of buffer + padding needs */
        bytes_to_read = 256-32;
    EVP_EncryptUpdate(ctx, buf, &bytes_written, poem+data_read, bytes_to_read);
    data_read = data_read + bytes_to_read;
    if (data_len == data_read) {
        int extra_bytes_written;
        EVP_EncryptFinal_ex(ctx, buf+bytes_written, &extra_bytes_written);
        bytes_written = bytes_written + extra_bytes_written;
    }
    return bytes_written;
}
