#ifndef simple_rsa_h
#define simple_rsa_h
#include <openssl/bn.h> //BN multiprecision strucuts
#include <openssl/rsa.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <assert.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>


//simple invocation of RSA using the OpenSSL structs and API

#define MSG "chocolate and fig confections are yummy!!!"
void test_rsa_with_high_level_apis(void)
{
    EVP_CIPHER_CTX *pkc_ctx;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey;
    BIO *bp, *bp_mem;
    int len, ekl, ctl, ctl_total, ptl, ptl_total;
    unsigned char *d, *e, *iv, **ek, *ct, *pt, *msg;

    //SET UP ALGORITHM CONTEXT:
    assert((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) != NULL);//we want an RSA algorithm context with NULL engine
    assert(EVP_PKEY_keygen_init(ctx) > 0);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 512) > 0);//sets the RSA key BIT length for RSA key generation to bits
    assert(EVP_PKEY_keygen(ctx, &pkey) > 0);//now actually generate RSA params and store in pkey
    
    //LET'S SEE WHAT WE HAVE:
    assert(bp = BIO_new_fp(stdout, BIO_NOCLOSE));//ptr uses standard out
    assert(EVP_PKEY_print_private(bp, pkey, 0, NULL)); // we can write this to a file stream, parse and use BN_mod_exp....
    
    //GET encrypted public and private exponents:
    assert(bp_mem = BIO_new(BIO_s_mem()));//alloc new bio ptr that uses memory for i/o
    assert(PEM_write_bio_PrivateKey(bp_mem, pkey, NULL, NULL, 0, 0, NULL));//write (private exponent d) to bp_mem without encrypting it.
    len = BIO_pending(bp_mem) + 1;//return the amount of pending data
    assert(len > 300);
    assert(d = (unsigned char *)malloc(sizeof(char)*len));
    assert(BIO_read(bp_mem, d, len));
    assert(PEM_write_bio_PUBKEY(bp_mem, pkey));//write (public exponent e) to bp_mem without encrypting it.
    len = BIO_pending(bp_mem) + 1;
    assert(len > 100);
    assert(e = (unsigned char *)malloc(sizeof(char)*len));
    assert(BIO_read(bp_mem, e, len));
    //LET'S SEE:
    printf("%s\n", d);
    printf("%s\n", e);
    
    //ENCRYPT: many ways... BN_mod_exp(cipher_text, plain_text, e, n, context)
    //Let's encrypt 1 Shared Secret Key:
    //The public key must be RSA because it is the only OpenSSL public key algorithm that supports key transport.
    //EVP_SealInit encrypts a randomly generated secret key using the cipher specified:
    assert(pkc_ctx = EVP_CIPHER_CTX_new());//PKC high level encryption
    assert(iv = (unsigned char *) malloc(EVP_MAX_IV_LENGTH));//malloc iv for cipher of choice
    assert(ek = (unsigned char **) malloc(sizeof(unsigned char *)));
    assert(ek[0] = (unsigned char *) malloc(EVP_PKEY_size(pkey)));//array of buffers (cipher texts: each SSK is encrpyted with the public key)
    assert(EVP_SealInit(pkc_ctx, EVP_aes_256_cbc(), ek, &ekl, iv, &pkey, 1) == 1);//size of ek[i] written to ekl[i] ary.
    printf("PKC_ENC_SSK:\n %s\n", ek[0]);
    //LETS write some plaint text to encrypt with out shared secret
    len = strlen(MSG) + 1 + EVP_MAX_IV_LENGTH;
    assert(msg = (const unsigned char *)malloc(sizeof(const unsigned char)*len));
    strncpy(msg,MSG,len-1);
    *(msg + len) = '\0';
    assert(ct = (unsigned char *)malloc(EVP_PKEY_size(pkey)));
    assert(EVP_SealUpdate(pkc_ctx,ct,&ctl, msg, len)); ctl_total = ctl;
    printf("CT:%s\nCTL:%d\n",ct, ctl);
    assert(EVP_SealFinal(pkc_ctx, ct + ctl, &ctl)); ctl_total += ctl;
    printf("CT: %s\nCTL:%d\n",ct, ctl);

    //DECRYPT:
    assert(EVP_OpenInit(pkc_ctx, EVP_aes_256_cbc(), ek[0], ekl, iv, pkey));
    assert(pt = (unsigned char *) malloc(ctl_total + EVP_MAX_IV_LENGTH));
    assert(EVP_OpenUpdate(pkc_ctx, pt, &ptl, ct, ctl_total)); ptl_total = ptl;
    assert(EVP_OpenFinal(pkc_ctx, pt + ptl, &ptl)); ptl_total = ptl;
    
   assert(strncmp(pt, msg, strlen(MSG) == 0));//assert of PT == our orignal message :)
   printf("PT: %s \n", pt);
    
    //clean up memory
    BIO_free(bp);
    BIO_free(bp_mem);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    free(d);
    free(e);
    free(iv);
    free(ek);
    free(msg);
    free(ct);
    free(pt);
}
