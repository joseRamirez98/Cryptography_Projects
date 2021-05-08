# Cryptography_Projects
A repo for projects I have completed for my cryptography class.

# Project Descriptions
## SIV Authenticated Encryption
We have seen nonces used in CTR mode encryption and in Wegman-Carter authentication. These happen to be the most popular ways of encrypting and authenticating. The only requirement of a nonce is that it never repeat when using the same key. 

People make mistakes and an attacker may be able to leverage these mistakes to cause a repeated nonce. So, nonce-based cryptography worries many security experts. For this reason, researchers have come up with a more robust solution: the use of a "synthetic initialization vector" (SIV). The idea is to generate an authentication tag for the plaintext that is to be encrypted, and then use the authentication tag as the initialization vector for encryption. Here's an example construction in pseudocode.
```
// Encrypt and authenticate P using key K and nonce N
SIVEncrypt(K,N,P):
   tag = first 12 bytes of HMAC-SHA256(K,N||P)  // tag for concatenation of N and P
   C = AES128-CTR(K,tag,P)
   return (C,tag)
```
### Assignment
Implement the above pseudocode and its inverse using OpenSSL and the following C headers.
```
void aes128ctr_hmacsha256_siv_encrypt(unsigned char *k,       // 16 byte key
                                      unsigned char *n,       // 12 byte nonce
                                      unsigned char *p,       // pbyte bytes plaintext
                                      int            pbytes,  // plaintext bytes
                                      unsigned char *tag,     // 12 byte authentication tag
                                      unsigned char *c)       // pbytes byte ciphertext

// Returns 0 is authentication fails, non-zero if it succeeds
int aes128ctr_hmacsha256_siv_decrypt(unsigned char *k,       // 16 byte key
                                     unsigned char *n,       // 12 byte nonce
                                     unsigned char *c,       // cbyte bytes ciphertext
                                     int            cbytes,  // ciphertext bytes
                                     unsigned char *tag,     // 12 byte authentication tag
                                     unsigned char *p)       // pbytes byte plaintext
```                                     
Decryption should write the AES128-CTR decryption result to p and then verify that the tag is correct for it. If authentication fails return 0 and if authentication shows the plaintext is valid, return any non-zero value.

## Implementing HMAC using OpenSSL
Not that long ago, HMAC was the most popular algorithm for generating authentication tags. It has since been overtaken by Wegman-Carter authentication, but is still embedded in many standards. In this assignment, you will get more practice using OpenSSL and learn the HMAC algorithm.

### Assignment
Implement HMAC with the following function header
```
 unsigned char *hmac_taggen(const EVP_MD *evp_md, const void *key,
                            int key_len, const unsigned char *d, size_t n,
                             unsigned char *md, unsigned int *md_len)
```
In OpenSSL's interfaces, cryptographic algorithms typically allow you to supply a sequence of chunks of input and then finalize the operation when the data is complete. Sometimes OpenSSL provides a simpler interface for situations where you are only going to use an algorithm once and all data is available. This interface is such an example: you supply the key and data to be authenticated and it immediately provides the authentication tag.

The assignment is to implement your own version of this easy to use interface. The implementation is not allowed to call any HMAC functions and must instead implement the HMAC algorithm using the EVP Message Digests interface to do all of the cryptographic hashing.

NOTE: Currently, this is program does not test the case that the HMAC key length is greater than the underlying hash function's block length. It also does not test the case where one passes NULL to the md parameter (which the documentation says would require the use of a static array). Both of these are unusual situations.

## OpenSSL Decrypt
Write OpenSSL code to decrypt a ciphertext. Code that encrypts Lewis Caroll's Jabberwocky poem using the AES-256 block cipher and CBC mode is provided. The code will encrypt the poem, break the ciphertext into chunks, and send the chunks to you one at a time.
```
EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       int *outl, const unsigned char *in, int inl);
```
The key thing to know about this function is that you pass a pointer to the ciphertext chunk that I give you as in and the number of bytes I give you as inl and this function writes plaintext bytes to out and the number of bytes written to outl. Because CBC produces output one 16-byte block at a time, outl will be a multiple of 16 and may not match inl. OpenSSL will buffer any unwritten output and output it with a later call.

The file server.c with the following functions will be available.
```
/* Call before any other server functions. Initializes encryption. */
void server_init();
​
/* Call after all other server functions. Frees resources. */
void server_close();
​
/* Writes 16 bytes to buf which will be used for this message's IV */
void server_get_cbc_iv(void *buf);
​
/* Writes 32 bytes to buf which will be used for this message's AES-256 key */
void server_get_key(void *buf);
​
/* Returns non-zero if no more data remains and zero if more data remains */
int server_done();
​
/* Receive next chunk of the ciphertext. Return value is 1 to 256 and is the */
/* number of bytes written to buf. It is an error to call this function when */
/* server_done() is non-zero (ie, true). */
int server_next_chunk(void *buf);
```
### Assignment 
Write a C file client.c with a main program that: 
- calls ```server_init``` to initialize my server.
- calls ```server_get_cbc_iv``` and ```server_get_key``` to get the IV and key used for encryption
- while ```server_done``` returns 0 (ie, is false), call ```server_next_chunk``` to get the next chunk of the ciphertext.
