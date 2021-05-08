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
