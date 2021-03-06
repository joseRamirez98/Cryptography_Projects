#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* print the buffer in ASCII */
void pbuf(void *p, unsigned len, const void *s)
{
    unsigned i;
    if (s)
        printf("%s", (char *)s);
    for (i = 0; i < len; i++)
        printf("%d ", (((unsigned char *)p)[i]));
    printf("\n");
}

/*
Encrypt the plaintext. Store the first 12 bytes of the
message digest generated by HMAC into the tag. Store the
encrypted text into the c paramter variable.

PARAMETERS:
__________________________________________
   k = 16 byte key
   n = 12 byte nonce
   P = pbyte bytes plaintext
   pbytes = plaintext bytes
   tag = 12 byte authentication tag
   c = cbytes byte ciphertext
*/
void aes128ctr_hmacsha256_siv_encrypt(unsigned char *k,       
                                      unsigned char *n,       
                                      unsigned char *p,       
                                      int            pbytes,  
                                      unsigned char *tag,     
                                      unsigned char *c) {
    unsigned char md_result[EVP_MAX_MD_SIZE];
    int ct_bytes_written = 0;
    int len;
    unsigned char iv[16] = {0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x01};

    /* Create a message digest with the nonce and 
       plaintext.
    */
    HMAC_CTX *mdctx = HMAC_CTX_new();
    HMAC_Init_ex(mdctx, k, 16, EVP_sha256(), NULL);
    HMAC_Update(mdctx, n, 12);
    HMAC_Update(mdctx, p, pbytes);
    HMAC_Final(mdctx, md_result, NULL);
    /* copy the first 12 bytes from the message digest
       into the tag
    */
    memcpy(tag, md_result, 12);
    
    /* copy 12 bytes of the tag into the iv */
    memcpy(iv, tag, 12);

    /* Encrypte the plaintext and store it the c parameter
       variable.
    */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, k, iv);
    EVP_EncryptUpdate(ctx, c, &len, p, pbytes);
    ct_bytes_written = ct_bytes_written + len;
    EVP_EncryptFinal_ex(ctx, c + ct_bytes_written, &len);
    ct_bytes_written = ct_bytes_written + len;
    
    
    // Free memory, zero sensitive stack elements
    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_free(mdctx);
    OPENSSL_cleanse(md_result, sizeof(md_result));
    OPENSSL_cleanse(iv, sizeof(iv));
}

/* 
Decrypt the cipher text and store the plaintext in the
p parameter variable. Authenticate the plaintext by 
generating a tag with the decrypted ciphertext. If the
newly generated tag matches the tag passed through the
parameters, then authentication was successful.
Returns 0 if authentication fails, non-zero if it succeeds

PARAMETERS:
__________________________________________
   k = 16 byte key
   n = 12 byte nonce
   c = cbyte bytes ciphertext
   cbytes = ciphertext bytes
   tag = 12 byte authentication tag
   p = pbytes byte plaintext
*/

int aes128ctr_hmacsha256_siv_decrypt(unsigned char *k,       
                                     unsigned char *n,       
                                     unsigned char *c,       
                                     int            cbytes,  
                                     unsigned char *tag,     
                                     unsigned char *p){
    unsigned char md_result[EVP_MAX_MD_SIZE];
    unsigned char tag_confirm[12];
    unsigned char iv[16] = {0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x01};
    int bytes_written = 0;
    int len; // store the length of decrypted bytes
    
    /* copy 12 bytes from tag into the iv */
    memcpy(iv, tag, 12);

    /* Decrypt the cipher text and store it in the
       p variable passed through parameter.
    */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, k, iv);
    EVP_DecryptUpdate(ctx, p, &len, c, cbytes);
    bytes_written = bytes_written + len;
    EVP_DecryptFinal_ex(ctx, p + bytes_written, &len);
    bytes_written = bytes_written + len;

    /* Create a message digest with the decrypted
       ciphertext.
    */
    HMAC_CTX *mdctx = HMAC_CTX_new();
    HMAC_Init_ex(mdctx, k, 16, EVP_sha256(), NULL);
    HMAC_Update(mdctx, n, 12);
    HMAC_Update(mdctx, p, cbytes);
    HMAC_Final(mdctx, md_result, NULL);
    
    /* copy the first 12 bytes from the message digest */
    memcpy(tag_confirm, md_result, 12);
    /* Zero return value from memcp means strings are equal. */
    int result = !memcmp(tag_confirm, tag, 12);

    /* Free memory, zero sensitive stack elements */
    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_free(mdctx);
    OPENSSL_cleanse(md_result, sizeof(md_result));
    OPENSSL_cleanse(iv, sizeof(iv));  
    OPENSSL_cleanse(tag_confirm, sizeof(tag_confirm));                      
    
    /* Zero return value means failed authentication. */
    return result;                                 
}


int main() {
    unsigned char key[16] = "0123456789abcdef";  // Receive SHA-2-256 hash of user pass phrase 
    unsigned char nonce[12] = "ABCDEFGHIJKL";
    unsigned char plaintext[11] = "Hello world";
    unsigned char ciphertext[11];
    unsigned char plaintext_confirm[11];         // Decrypted cipher text
    unsigned char tag[12];


    aes128ctr_hmacsha256_siv_encrypt(key, nonce, plaintext, sizeof(plaintext), tag, ciphertext);

   /* If Decryption function returns a zero, authentication failed. */
    if(!aes128ctr_hmacsha256_siv_decrypt(key, nonce, ciphertext, sizeof(ciphertext), tag, plaintext_confirm)) {
        fprintf(stderr, "Authentication failed.\n");
        return -1;
    }
    printf("Successfully decrypted and authenticated ciphertext.\n");
    pbuf(plaintext, sizeof(plaintext), "Original Plain text: ");
    pbuf(plaintext_confirm, sizeof(plaintext_confirm), "Decrypted Plain text: ");
    return 0;
}
