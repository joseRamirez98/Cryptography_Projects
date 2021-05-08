#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

 unsigned char *hmac_taggen(const EVP_MD *evp_md, const void *key,
                            int key_len, const unsigned char *d, size_t n,
                            unsigned char *md, unsigned int *md_len) {
    
    /*
        Create a message digest context, and set the underlying algorithm
        to the one based of the evp_md variable.
    */
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, evp_md, NULL);
    
    // The output size of the hash function (e.g. 20 bytes for SHA-1)
    const int digestsize = EVP_MD_size(evp_md); 
    // The block size of the hash function (e.g. 64 bytes for SHA-1)
    const int block_size = EVP_MD_block_size(evp_md);
    
    /*
        Create the padded key, inner and outter char arrays that are of size
        block_size.
    */
    unsigned char padded_key[block_size];
    unsigned char o_key_pad[block_size];
    unsigned char i_key_pad[block_size];

    /* Set all the bytes in the padded array, i_pad, o_pad
       to the hex value 0. Copy the key into the padded key.
    */

    memset(i_key_pad, 0x00, block_size);    // set all the bytes in the padded array to 0.
    memset(o_key_pad, 0x00, block_size);    // set all the bytes in the padded array to 0.
    memset(padded_key, 0x00, block_size);   // set all the bytes in the padded array to 0.
    memcpy(padded_key, key, key_len);       // copy the key into the padded key array.
  
    /*
        o_key_pad ← key xor [0x5c * blockSize]   // Outer padded key
        i_key_pad ← key xor [0x36 * blockSize]   // Inner padded key
    */
    for(int i = 0; i < block_size; i++) {
        o_key_pad[i] = padded_key[i] ^ 0x5c;
        i_key_pad[i] = padded_key[i] ^ 0x36;
    }
    /*
       Perform this part of the HMAC algorithm:
       hash(i_key_pad ∥ message)
    */   
    EVP_DigestUpdate(mdctx, i_key_pad, block_size); // hash the i_key_pad
    EVP_DigestUpdate(mdctx, d, n);                  // hash the message
    EVP_DigestFinal_ex(mdctx, md, md_len);          // hash any remaning bytes on the message digest context buffer
    EVP_DigestInit_ex(mdctx, evp_md, NULL);         // must re-initialize since EVP_DigestFinal_ex was called
    

    /*
        Perform this part of the HMAC algorithm:
        hash(o_key_pad ∥ hash(i_key_pad ∥ message))
    */
    EVP_DigestUpdate(mdctx, o_key_pad, block_size); // hash the o_key_pad
    EVP_DigestUpdate(mdctx, md, digestsize);        // hash the message digest
    EVP_DigestFinal_ex(mdctx, md, md_len);          // hash any remaning bytes on the message digest context buffer
    EVP_MD_CTX_free(mdctx);                         // free the message digest context
    
    // return final hash value
    return md;
}

int main() {
    const unsigned char key[] = "ahfbdufefgsa"; //{1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6};
    const int keylen = 12;
    const unsigned char data[44] = "The quick brown fox jumps over the lazy dog!"; 
    const int data_len = 43;

    unsigned char d_out[EVP_MAX_MD_SIZE];
    unsigned char d_out2[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    // Calculate our HMAC-SHA1
    hmac_taggen(EVP_sha1(), key, keylen, data, data_len, d_out, &md_len);
    printf("Using hmac_taggen:  ");
    for (unsigned int i = 0; i < md_len; i++)
    {
        printf("%02x", d_out[i]);
    }
    printf("\n");

    // Calculate a real HMAC-SHA1
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, keylen, EVP_sha1(), NULL);
    HMAC_Update(ctx, data, data_len);
    HMAC_Final(ctx, d_out2, &md_len);
    printf("Using HMAC library: ");
    for (unsigned int i = 0; i < md_len; i++)
    {
        printf("%02x", d_out2[i]);
    }
    HMAC_CTX_free(ctx);
    printf("\n");
    
    return 0;
}
