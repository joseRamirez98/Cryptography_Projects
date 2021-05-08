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
