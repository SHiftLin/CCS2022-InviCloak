#pragma once
#include "ngx_http_invicloak_util.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>

#define public_key_header "-----BEGIN PUBLIC KEY-----\n"
#define public_key_footer "\n-----END PUBLIC KEY-----"
#define private_key_header "-----BEGIN PRIVATE KEY-----\n"
#define private_key_footer "\n-----END PRIVATE KEY-----"
#define public_key_header_BYTES (sizeof(public_key_header) - 1)
#define public_key_footer_BYTES (sizeof(public_key_footer) - 1)
#define private_key_header_BYTES (sizeof(private_key_header) - 1)
#define private_key_footer_BYTES (sizeof(private_key_footer) - 1)
#define public_key_title_BYTES                                                 \
    (public_key_header_BYTES + public_key_footer_BYTES)
#define private_key_title_BYTES                                                \
    (private_key_header_BYTES + private_key_footer_BYTES)
#define cloak_max_pem_BYTES 250U

#define cloak_IV_BYTES 16U
#define cloak_tag_BYTES 16U
#define cloak_sign_BYTES 64U
#define cloak_aead_key_BYTES 32U
#define cloak_stek_BYTES cloak_aead_key_BYTES
#define cloak_ticket_BYTES                                                     \
    (cloak_aead_key_BYTES + cloak_sessionID_BYTES + cloak_tag_BYTES)
#define cloak_max_padding_BYTES 0U // 32U AES-GCM does not require padding
#define cloak_leading_BYTES (sizeof(u_int) << 1)
#define cloak_record_default_BYTES (32 * 1024)

/* TODO: Free ctx after ngx_check fails*/

void
ngx_export_public_key(ngx_str_t *gb_pem, EVP_PKEY *key)
{
    BIO *bp = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bp, key);
    BIO_read(bp, gb_pem->data, public_key_header_BYTES); /* remove header */
    gb_pem->len = BIO_pending(bp);
    BIO_read(bp, gb_pem->data, gb_pem->len);
    gb_pem->len -= public_key_footer_BYTES; /* remove footer */
    BIO_free_all(bp);
}

EVP_PKEY *
ngx_import_crypto_key(ngx_str_t pem, bool private)
{
    BIO      *bp = BIO_new_mem_buf(pem.data, pem.len);
    EVP_PKEY *key = (private) ? PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL)
                              : PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
    BIO_free_all(bp);
    return key;
}

static ngx_int_t
ngx_ECDH_derive_key(ngx_str_t K, EVP_PKEY *keypair, ngx_str_t ga_pem)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *ga = NULL;
    ngx_check(ga = ngx_import_crypto_key(ga_pem, false));

    ngx_check(ctx = EVP_PKEY_CTX_new(keypair, NULL));
    ngx_check_1(EVP_PKEY_derive_init(ctx));
    ngx_check_1(EVP_PKEY_derive_set_peer(ctx, ga));
    // ngx_check_1(EVP_PKEY_derive(ctx, NULL, &len));
    ngx_check_1(EVP_PKEY_derive(ctx, K.data, &K.len));

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(ga);

    char info[] = "ap traffic";
    ngx_check(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL));
    ngx_check_1(EVP_PKEY_derive_init(ctx));
    ngx_check_1(EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()));
    // ngx_check_1(EVP_PKEY_CTX_set1_hkdf_salt(ctx, "salt", 4));
    ngx_check_1(EVP_PKEY_CTX_set1_hkdf_key(ctx, K.data, K.len));
    ngx_check_1(EVP_PKEY_CTX_add1_hkdf_info(ctx, info, strlen(info)));
    ngx_check_1(EVP_PKEY_derive(ctx, K.data, &K.len));

    EVP_PKEY_CTX_free(ctx);
    
    return NGX_OK;
}

static int
sigtoraw(u_char *sign, ECDSA_SIG *signature)
{
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    ECDSA_SIG_get0(signature, (const BIGNUM **)&r, (const BIGNUM **)&s);
    int r_len = BN_bn2binpad(r, sign, cloak_sign_BYTES / 2);
    int s_len = BN_bn2binpad(s, sign + r_len, cloak_sign_BYTES / 2);
    return r_len + s_len;
}

static ngx_int_t
ngx_ECDSA_sign(ngx_str_t *sign, ngx_str_t msg, EVP_PKEY *private_key)
{
    EVP_MD_CTX *mdctx;
    ECDSA_SIG  *signature;
    u_char      dgst[EVP_MAX_MD_SIZE];
    u_int       dgst_len;

    ngx_check(mdctx = EVP_MD_CTX_create());
    ngx_check(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    ngx_check(EVP_DigestUpdate(mdctx, msg.data, msg.len));
    ngx_check(EVP_DigestFinal(mdctx, dgst, &dgst_len));
    ngx_check(signature = ECDSA_do_sign(
                  dgst, dgst_len, (EC_KEY *)EVP_PKEY_get0_EC_KEY(private_key)));
    sign->len = sigtoraw(sign->data, signature);

    EVP_MD_CTX_free(mdctx);
    ECDSA_SIG_free(signature);
    /* get0 must not be free */
    return NGX_OK;
}

static ngx_int_t
ngx_gen_ECDH_keypair(EVP_PKEY **keypair)
{
    EVP_PKEY_CTX *pctx = NULL, *kctx = NULL;
    EVP_PKEY     *params = NULL;
    *keypair = NULL;

    ngx_check((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)));
    ngx_check_1(EVP_PKEY_paramgen_init(pctx));
    ngx_check_1(
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1));
    ngx_check(EVP_PKEY_paramgen(pctx, &params));
    ngx_check(kctx = EVP_PKEY_CTX_new(params, NULL));
    ngx_check_1(EVP_PKEY_keygen_init(kctx));
    ngx_check_1(EVP_PKEY_keygen(kctx, keypair));

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    return NGX_OK;
}

static ngx_int_t
ngx_encrypt_AES_GCM_256(ngx_str_t *cipher, ngx_str_t msg, ngx_str_t IV,
                        ngx_str_t *tag, ngx_str_t K)
{
    if (cipher->len < msg.len)
        return NGX_ERROR;

    int             len = 0;
    EVP_CIPHER_CTX *ctx;

    ngx_check(ctx = EVP_CIPHER_CTX_new());
    ngx_check(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
    ngx_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV.len, NULL));
    ngx_check(EVP_EncryptInit_ex(ctx, NULL, NULL, K.data, IV.data));
    ngx_check(EVP_EncryptUpdate(ctx, cipher->data, &len, msg.data, msg.len));
    cipher->len = len;
    ngx_check(EVP_EncryptFinal_ex(ctx, cipher->data + len, &len));
    cipher->len += len;
    ngx_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, cloak_tag_BYTES,
                                  tag->data));

    EVP_CIPHER_CTX_free(ctx);
    return NGX_OK;
}

static ngx_int_t
ngx_decrypt_AES_GCM_256(ngx_str_t *msg, ngx_str_t cipher, ngx_str_t IV,
                        ngx_str_t tag, ngx_str_t K)
{
    if (msg->len < cipher.len)
        return NGX_ERROR;
    int             len = 0;
    EVP_CIPHER_CTX *ctx;

    ngx_check(ctx = EVP_CIPHER_CTX_new());
    ngx_check(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
    ngx_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV.len, NULL));
    ngx_check(EVP_DecryptInit_ex(ctx, NULL, NULL, K.data, IV.data));
    ngx_check(EVP_DecryptUpdate(ctx, msg->data, &len, cipher.data, cipher.len));
    msg->len = len;
    ngx_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                  cloak_tag_BYTES, // cannot be tag.len
                                  tag.data));
    int ret = EVP_DecryptFinal_ex(ctx, msg->data + len, &len);
    msg->len += len;

    EVP_CIPHER_CTX_free(ctx);
    ngx_check(ret);
    return NGX_OK;
}
