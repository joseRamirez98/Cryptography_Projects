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
Decryption should write the AES128-CTR decryption result to p and then verify that the tag is correct for it. If authentication fails return 0 and if authentication shows the plaintext is valid return any non-zero value.
