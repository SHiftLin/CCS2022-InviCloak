#include "ngx_http_invicloak_context.h"
#include "ngx_http_invicloak_crypto.h"
#include "ngx_http_invicloak_session.h"
#include "ngx_http_invicloak_util.h"

static ngx_command_t ngx_http_cloak_commands[] = {
    {ngx_string("cloakhello"),                        /* name */
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,               /* type */
     ngx_conf_set_clienthello,                        /* set */
     NGX_HTTP_LOC_CONF_OFFSET,                        /* conf */
     offsetof(ngx_http_cloak_loc_conf_t, hello_flag), /* offset */
     NULL},                                           /* post */

    {ngx_string("cloakenc"),                                /* name */
     NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG, /* type */
     ngx_conf_set_cloakenc,                                 /* set */
     NGX_HTTP_LOC_CONF_OFFSET,                              /* conf */
     offsetof(ngx_http_cloak_loc_conf_t, enc_flag),         /* offset */
     NULL},                                                 /* post */

    {ngx_string("cloaksign"),                               /* name */
     NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG, /* type */
     ngx_conf_set_flag_slot,                                /* set */
     NGX_HTTP_LOC_CONF_OFFSET,                              /* conf */
     offsetof(ngx_http_cloak_loc_conf_t, sign_flag),        /* offset */
     NULL},                                                 /* post */

    {ngx_string("cloakrecord"),                        /* name */
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,              /* type */
     ngx_conf_set_size_slot,                           /* set */
     NGX_HTTP_MAIN_CONF_OFFSET,                        /* conf */
     offsetof(ngx_http_cloak_ms_conf_t, record_bytes), /* offset */
     NULL},

    {ngx_string("cloakstate"),                             /* name */
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE3 | NGX_CONF_TAKE4, /* type */
     ngx_conf_set_cloakstate,                              /* set */
     NGX_HTTP_MAIN_CONF_OFFSET,                            /* conf */
     offsetof(ngx_http_cloak_ms_conf_t, state),            /* offset */
     NULL},                                                /* post */

    ngx_null_command /* null */
};

static ngx_http_module_t ngx_http_cloak_module_ctx = {
    ngx_http_cloak_pre_conf_init,  /* preconfiguration */
    ngx_http_cloak_post_conf_init, /* postconfiguration */

    ngx_http_cloak_create_ms_conf, /* create main configuration */
    ngx_http_cloak_init_main_conf, /* init main configuration */

    ngx_http_cloak_create_ms_conf, /* create server configuration */
    ngx_http_cloak_merge_srv_conf, /* merge server configuration */

    ngx_http_cloak_create_loc_conf, /* create location configuration */
    NULL                            /* merge location configuration */
};

ngx_module_t ngx_http_cloak_module = {
    NGX_MODULE_V1,
    &ngx_http_cloak_module_ctx, /* module context */
    ngx_http_cloak_commands,    /* module directives */
    NGX_HTTP_MODULE,            /* module type */
    NULL,                       /* init master */
    NULL,                       /* init module */
    NULL,                       /* init process */
    NULL,                       /* init thread */
    NULL,                       /* exit thread */
    NULL,                       /* exit process */
    NULL,                       /* exit master */
    NGX_MODULE_V1_PADDING       /*  */
};


static ngx_int_t
ngx_http_cloak_request_header_handler(ngx_http_request_t           *r,
                                      ngx_http_cloak_request_ctx_t *ctx,
                                      ngx_http_cloak_state_conf_t  *state)
{
    /*
    ngx_str_t name = ngx_string("ticket");
    ngx_str_t ticket_hex, ticket = ngx_create_str(r->pool, cloak_ticket_BYTES);
    ngx_int_t rc = ngx_http_parse_multi_header_lines(&(r->headers_in.cookies),
                                                     &name, &ticket_hex);
    if (rc == NGX_DECLINED)
        return NGX_HTTP_FORBIDDEN;
    ngx_hextobin(ticket.data, ticket_hex.data, ticket_hex.len);
    */

    ngx_str_t name = ngx_string("cloakparams");
    ngx_str_t params_hex;
    /*
    ngx_str_t params =
        ngx_create_str(r->pool, cloak_IV_BYTES + cloak_ticket_BYTES);
    */
    ngx_str_t params =
        ngx_create_str(r->pool, cloak_IV_BYTES + cloak_sessionID_BYTES);
    ngx_int_t rc =
        ngx_cloak_find_header(&(r->headers_in.headers), &name, &params_hex);
    if (rc == NGX_DECLINED)
        return NGX_HTTP_FORBIDDEN;
    ngx_hextobin(params.data, params_hex.data, params_hex.len);

    ctx->IV_in = (ngx_str_t){cloak_IV_BYTES, params.data};
    ctx->sID = (ngx_str_t){cloak_sessionID_BYTES, params.data + cloak_IV_BYTES};
    ctx->sessions = state->shds->sessions;
    ctx->snode = ngx_http_cloak_session_lookup(ctx->sessions, &(ctx->sID));
    if (ctx->snode == NULL) {
        return NGX_HTTP_FORBIDDEN;
        /* check ticket (PSK Identity) and then resume the conenction */
    }
    ctx->K = ctx->snode->K;

    /*
        ngx_str_t ticket = {cloak_ticket_BYTES, params.data + cloak_IV_BYTES};
        ngx_str_t KsID =
            ngx_create_str(r->pool, cloak_aead_key_BYTES +
       cloak_sessionID_BYTES); rc = ngx_decrypt_AES_GCM_256( &KsID,
       (ngx_str_t){KsID.len, ticket.data}, zeroIV, (ngx_str_t){cloak_tag_BYTES,
       ticket.data + KsID.len}, state->stek); if (rc != NGX_OK) return
       NGX_HTTP_FORBIDDEN; ctx->K = (ngx_str_t){cloak_aead_key_BYTES,
       KsID.data}; ctx->sID = (ngx_str_t){cloak_sessionID_BYTES, KsID.data +
       cloak_aead_key_BYTES};
    */

    ngx_str_t         buffer = {0, NULL};
    ngx_table_elt_t **cookies = r->headers_in.cookies.elts;
    for (ngx_uint_t i = 0; i < r->headers_in.cookies.nelts; i++) {
        ngx_str_t *value = &(cookies[i]->value);
        if (value->len * 2 > buffer.len)
            buffer = (ngx_str_t)ngx_create_str(
                r->pool, max(value->len * 2, buffer.len * 2));
        for (ngx_uint_t lp = 0, rp = 0; lp < value->len; lp = rp + 1) {
            if (value->data[lp] != '=') {
                rp = lp;
                continue;
            }
            rp = ++lp;
            while (rp < value->len && value->data[rp] != ';')
                rp++;
            ngx_uint_t len =
                ngx_hextobin(buffer.data, value->data + lp, rp - lp);
            if (len < cloak_tag_BYTES)
                continue;
            ngx_str_t cipher = {len - cloak_tag_BYTES, buffer.data},
                      tag = {cloak_tag_BYTES, buffer.data + cipher.len},
                      cookie = {cipher.len, buffer.data + len};
            rc = ngx_decrypt_AES_GCM_256(&cookie, cipher, zeroIV, tag, ctx->K);
            if (rc != NGX_OK)
                continue;
            ngx_memcpy(value->data + lp, cookie.data, cookie.len);
            ngx_uint_t k = lp + cookie.len;
            if (rp < value->len)
                value->data[k++] = ';';
            while (k <= rp && k < value->len)
                value->data[k++] = ' ';
        }
    }

    return NGX_OK;
}

static bool
ngx_http_cloak_verify_message(ngx_http_cloak_request_ctx_t *ctx,
                              ngx_str_t                    *leading)
{
    /* little end and big end
     * int timestamp = *((int *)plain.data);
     * int rID = *((int *)(plain.data + sizeof(int)));
     */
    u_int  timestamp = ngx_bytestoi(leading->data);
    u_int  rID = ngx_bytestoi(leading->data + sizeof(u_int));
    time_t now = time(NULL);
    if (timestamp + cloak_requestID_timeout < now) {
        // return false;
    }
    return ngx_http_cloak_verify_request_session(ctx->sessions, ctx->snode, now,
                                                 rID);
}

/* Will be called before post handler */
static ngx_int_t
ngx_http_cloak_request_decryption_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_cloak_loc_conf_t *cloak_conf =
        ngx_http_get_module_loc_conf(r, ngx_http_cloak_module);

    if (cloak_conf->enc_flag != 1 || cloak_conf->sign_flag == 1 ||
        cloak_conf->hello_flag == 1 || r != r->main)
        return ngx_http_next_request_body_filter(r, in);

    ngx_http_cloak_request_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_cloak_module);
    if (ctx == NULL || r->headers_in.content_length_n <
                           (off_t)(cloak_leading_BYTES + cloak_tag_BYTES))
        return NGX_HTTP_FORBIDDEN;

    if (ctx->evp == NULL) {
        ngx_check(ctx->evp = EVP_CIPHER_CTX_new());
        ngx_check(
            EVP_DecryptInit_ex(ctx->evp, EVP_aes_256_gcm(), NULL, NULL, NULL));
        ngx_check(EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_GCM_SET_IVLEN,
                                      ctx->IV_in.len, NULL));
        ngx_check(EVP_DecryptInit_ex(ctx->evp, NULL, NULL, ctx->K.data,
                                     ctx->IV_in.data));
        ctx->buffer =
            (ngx_str_t)ngx_create_str(r->pool, cloak_initial_buffer_BYTES);
        ctx->leading = (ngx_str_t)ngx_create_str(r->pool, cloak_leading_BYTES);
        ctx->count = ctx->remain = 0;
    }

    bool       last_buf = false;
    int        outl = 0;
    ngx_str_t *cipher = &(ctx->buffer);

    for_each_buf(cl, in)
    {
        last_buf = cl->buf->last_buf;
        const size_t len = ngx_buf_special(cl->buf) ? 0 : ngx_buf_size(cl->buf);
        if (len == 0)
            continue;

        if (ctx->tag_in) {
            ngx_memcpy(ctx->buffer.data + ctx->buffer.len, cl->buf->pos, len);
            ctx->buffer.len += len;
            cl->buf->pos = cl->buf->last;
            continue;
        }

        if (cipher->len < len)
            (*cipher) =
                (ngx_str_t)ngx_create_str(r->pool, max(2 * cipher->len, len));

        size_t p = min(
            r->headers_in.content_length_n - cloak_tag_BYTES - ctx->count, len);
        ngx_memcpy(cipher->data, cl->buf->pos, p);
        EVP_DecryptUpdate(ctx->evp, cl->buf->pos, &outl, cipher->data, p);
        cl->buf->last = cl->buf->pos + outl;

        if (p < len) {
            ngx_memcpy(ctx->buffer.data, cl->buf->pos + p, len - p);
            ctx->buffer.len = len - p;
            ctx->tag_in = 1;
        }

        if (ctx->count < cloak_leading_BYTES) {
            int c = min(cloak_leading_BYTES - ctx->count, (size_t)outl);
            ngx_memcpy(ctx->leading.data + ctx->count, cl->buf->pos, c);
            cl->buf->pos += c;
            ctx->count += p;

            if (ctx->count >= cloak_leading_BYTES) {
                bool verify = ngx_http_cloak_verify_message(ctx, &ctx->leading);
                if (!verify)
                    return NGX_HTTP_FORBIDDEN;
            }
        } else
            ctx->count += p;
    }
    if (last_buf) {
        ngx_check(EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_GCM_SET_TAG,
                                      cloak_tag_BYTES, /* fixed tag length */
                                      ctx->buffer.data));
        int ret = EVP_DecryptFinal_ex(
            ctx->evp, ctx->buffer.data + cloak_tag_BYTES, &outl);
        EVP_CIPHER_CTX_free(ctx->evp);
        ctx->evp = NULL; /* Important for output! */
        if (ret) {
            // if (r->headers_in.content_length_n >= 0) {
            r->headers_in.content_length_n = ctx->count - cloak_leading_BYTES;
            // cloak_tag_BYTES + cloak_leading_BYTES;
            // }
        } else
            return NGX_HTTP_FORBIDDEN;
    }

    return ngx_http_next_request_body_filter(r, in);
}

static ngx_int_t // NGX_HTTP_PREACCESS_PHASE
ngx_http_cloak_request_decryption_handler(ngx_http_request_t *r)
{
    ngx_http_cloak_loc_conf_t *cloak_conf =
        ngx_http_get_module_loc_conf(r, ngx_http_cloak_module);

    if (cloak_conf->enc_flag != 1 || cloak_conf->sign_flag == 1 ||
        cloak_conf->hello_flag == 1 || r != r->main ||
        r->method == NGX_HTTP_OPTIONS)
        return NGX_DECLINED;

    // ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
    //               "request handler called");

    ngx_http_cloak_ms_conf_t *ms_conf =
        ngx_http_get_module_main_conf(r, ngx_http_cloak_module);
    ngx_http_cloak_state_conf_t *state = ms_conf->state;

    ngx_http_cloak_request_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_cloak_module);
    ngx_create_request_ctx(ctx, r);

    ngx_int_t rc = ngx_http_cloak_request_header_handler(r, ctx, state);
    if (rc != NGX_OK)
        return rc;

    if (r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT)
        return NGX_DECLINED;
    /* GET */
    /* ngx_str_t body = r->args;
    const char name[] = "ciphertext"; */

    /* cipher: content - tag
     * content: timestamp rID message */
    /* ngx_str_t cipher_hex = ngx_cloak_get_arg_by_name(body, name); */

    ngx_str_t name = ngx_string("cipherquery"), cipher_hex = {0, NULL};
    ngx_cloak_find_header(&(r->headers_in.headers), &name, &cipher_hex);
    ngx_check(cipher_hex.data);
    ngx_check(cipher_hex.len >= 2 * (2 * sizeof(u_int) + cloak_tag_BYTES) + 1);
    ngx_str_t cipher = ngx_create_str(r->pool, cipher_hex.len / 2);
    cipher.len -= cloak_tag_BYTES; /* Bug fixed: Cannot merge it with above */
    ngx_str_t tag = {cloak_tag_BYTES, cipher.data + cipher.len};
    ngx_str_t plain = ngx_create_str(r->pool, cipher.len);

    ngx_hextobin(cipher.data, cipher_hex.data, 2 * cipher.len);
    ngx_hextobin(tag.data, cipher_hex.data + 2 * cipher.len + 1, 2 * tag.len);
    if (ngx_decrypt_AES_GCM_256(&plain, cipher, ctx->IV_in, tag, ctx->K))
        return NGX_HTTP_FORBIDDEN;

    if (!ngx_http_cloak_verify_message(ctx, &plain))
        return NGX_HTTP_FORBIDDEN;

    r->args = (ngx_str_t){plain.len - sizeof(u_int) * 2,
                          plain.data + sizeof(u_int) * 2};
    ngx_http_variable_value_t *vv =
        ngx_http_get_indexed_variable(r, cloak_conf->args_index);
    if (vv)
        vv->valid = 0; // make sure $args is not cached in the request

    return NGX_DECLINED;
}

static void
ngx_http_cloak_request_body_post_handler(ngx_http_request_t *r)
{
    ngx_http_cloak_request_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_cloak_module);
    if (ctx == NULL)
        ngx_http_finalize_request(r, NGX_ERROR);

    if (!ctx->done) {
        ctx->done = 1;
        ngx_http_core_run_phases(r);
    }
}

/*
static ngx_int_t
ngx_http_cloak_get_ticket(ngx_str_t ticket, ngx_str_t KsID, ngx_str_t stek)
{
    ngx_check(ticket.len >= KsID.len + cloak_tag_BYTES);

    ngx_str_t tag = {cloak_tag_BYTES, ticket.data + KsID.len};
    return ngx_encrypt_AES_GCM_256(&ticket, KsID, zeroIV, &tag, stek);
}
*/

static ngx_int_t
ngx_http_cloak_clienthello_handler(ngx_http_request_t *r)
{
    // ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
    //               "clienthello handler called");

    ngx_http_cloak_loc_conf_t *cloak_conf =
        ngx_http_get_module_loc_conf(r, ngx_http_cloak_module);

    if (cloak_conf->hello_flag != 1 || cloak_conf->sign_flag == 1 ||
        cloak_conf->enc_flag == 1)
        return NGX_DECLINED;

    ngx_http_cloak_ms_conf_t *ms_conf =
        ngx_http_get_module_main_conf(r, ngx_http_cloak_module);
    ngx_http_cloak_state_conf_t *state = ms_conf->state;
    if (state == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                      "No cloakstate in configuration! ");
        return NGX_DECLINED;
    }

    ngx_str_t body;
    if (r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT) {
        ngx_http_cloak_request_ctx_t *ctx =
            ngx_http_get_module_ctx(r, ngx_http_cloak_module);
        ngx_create_request_ctx(ctx, r);

        if (!ctx->done) {
            ngx_int_t rc = ngx_http_read_client_request_body(
                r, ngx_http_cloak_request_body_post_handler);
            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                /* error */
                ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "Reading request body error!");
                return rc;
            }
            return NGX_DONE;
        }
        body = ngx_cloak_load_whole_body(r);
    } else {
        body = r->args;
    }

    ngx_check(body.data);
    ngx_str_t ga_pem_arg = ngx_cloak_get_arg_by_name(body, "ga");
    ngx_check(ga_pem_arg.data);

    ngx_str_t gagb_pem = ngx_create_str(
        r->pool, ga_pem_arg.len + public_key_title_BYTES + cloak_max_pem_BYTES);

    ngx_memcpy(gagb_pem.data, public_key_header, public_key_header_BYTES);
    u_char *gadst = gagb_pem.data + public_key_header_BYTES;
    u_char *gasrc = ga_pem_arg.data;
    ngx_unescape_uri(&gadst, &gasrc, ga_pem_arg.len, NGX_UNESCAPE_URI);
    ngx_memcpy(gadst, public_key_footer, public_key_footer_BYTES);

    ngx_str_t ga_pem = {gadst - gagb_pem.data + public_key_footer_BYTES,
                        gagb_pem.data};
    ngx_str_t gb_pem = {cloak_max_pem_BYTES, gadst};

    ngx_str_t sign = ngx_create_str(r->pool, cloak_sign_BYTES);
    ngx_str_t KsID =
        ngx_create_str(r->pool, cloak_aead_key_BYTES + cloak_sessionID_BYTES);
    ngx_str_t K = {cloak_aead_key_BYTES, KsID.data};
    ngx_str_t sID = {cloak_sessionID_BYTES, KsID.data + cloak_aead_key_BYTES};
    // ngx_str_t ticket = ngx_create_str(r->pool, cloak_ticket_BYTES);

    EVP_PKEY *keypair = NULL;
    ngx_check_ok(ngx_gen_ECDH_keypair(&keypair));
    ngx_check_ok(ngx_ECDH_derive_key(K, keypair, ga_pem));
    ngx_export_public_key(&gb_pem, keypair);
    gagb_pem.data += public_key_header_BYTES;
    gagb_pem.len = gadst - gagb_pem.data + gb_pem.len;
    ngx_check_ok(ngx_ECDSA_sign(&sign, gagb_pem, state->dns_private_key));
    EVP_PKEY_free(keypair);

    ngx_check_ok(ngx_http_cloak_get_sessionID(sID, K, state->shds->sessions));

    // ngx_check_ok(ngx_http_cloak_get_ticket(ticket, KsID, state->stek));

    /*
    ngx_str_t name = ngx_string("ticket=");
    ngx_str_t cookie = ngx_create_str(
        r->pool, name.len + 2 * cloak_ticket_BYTES);
    ngx_memcpy(cookie.data, name.data, name.len * sizeof(u_char));
    ngx_hex_dump(cookie.data + name.len, ticket.data, ticket.len);

    ngx_table_elt_t *set_cookie = ngx_list_push(&r->headers_out.headers);
    ngx_check(set_cookie);
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value = cookie;
    set_cookie->hash = 1;
    */

    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    ngx_check(h);
    h->hash = 1; // when it is set to 0, the header will be omitted
    ngx_str_set(&h->key, "cloakparams");
    h->value = (ngx_str_t)ngx_create_str(r->pool, 2 * cloak_sessionID_BYTES);
    ngx_hex_dump(h->value.data, sID.data, sID.len);
    // h->value = (ngx_str_t)ngx_create_str(r->pool, 2 * cloak_ticket_BYTES);
    // ngx_hex_dump(h->value.data, ticket.data, ticket.len);

    r->headers_out.status = NGX_HTTP_OK;
    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK)
        return NGX_ERROR;

    ngx_buf_t *buf = /* sign gb */
        ngx_create_temp_buf(r->pool, 2 * sign.len + gb_pem.len /*+ sID.len*/);
    u_char *offset = ngx_hex_dump(buf->pos, sign.data, sign.len);
    ngx_memcpy(offset, gb_pem.data, gb_pem.len);
    offset += gb_pem.len;

    buf->last = offset;
    buf->last_buf = 1;
    buf->last_in_chain = 1;
    ngx_chain_t out = {buf, NULL};

    return ngx_http_output_filter(r, &out);
}


#define cloak_HTML_integrity_header "<!-- cloaksign: "
#define cloak_HTML_integrity_footer " -->"
#define cloak_JS_integrity_header "/* cloaksign: "
#define cloak_JS_integrity_footer " */"
#define cloak_HTML_integrity_header_BYTES                                      \
    (sizeof(cloak_HTML_integrity_header) - 1)
#define cloak_HTML_integrity_footer_BYTES                                      \
    (sizeof(cloak_HTML_integrity_footer) - 1)
#define cloak_JS_integrity_header_BYTES (sizeof(cloak_JS_integrity_header) - 1)
#define cloak_JS_integrity_footer_BYTES (sizeof(cloak_JS_integrity_footer) - 1)


/* Filter */
static ngx_int_t
ngx_http_cloak_output_header_integrity_filter(ngx_http_request_t *r)
{
    // if (r->headers_out.status != NGX_HTTP_OK || r != r->main)
    //     return ngx_http_next_output_body_filter(r, out);

    ngx_http_cloak_loc_conf_t *cloak_conf =
        ngx_http_get_module_loc_conf(r, ngx_http_cloak_module);

    if (cloak_conf->sign_flag != 1 || cloak_conf->enc_flag == 1 ||
        cloak_conf->hello_flag == 1)
        return ngx_http_next_output_header_filter(r);

    ngx_http_cloak_request_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_cloak_module);
    ngx_create_request_ctx(ctx, r);

    ngx_get_c_str(r->pool, type, r->headers_out.content_type);
    if (ngx_strstr(type, "html")) {
        ctx->type = 1;
        if (r->headers_out.content_length_n >= 0)
            r->headers_out.content_length_n +=
                cloak_HTML_integrity_header_BYTES + 2 * cloak_sign_BYTES +
                cloak_HTML_integrity_footer_BYTES;
    } else if (ngx_strstr(type, "javascript")) {
        ctx->type = 2;
        if (r->headers_out.content_length_n >= 0)
            r->headers_out.content_length_n += cloak_JS_integrity_header_BYTES +
                                               2 * cloak_sign_BYTES +
                                               cloak_JS_integrity_footer_BYTES;
    } else
        ctx->type = 3;
    return ngx_http_next_output_header_filter(r);
}

static ngx_str_t
ngx_http_cloak_output_cloakparam(ngx_http_request_t           *r,
                                 ngx_http_cloak_request_ctx_t *ctx)
{
    /*
    ngx_str_t cloakparams = (ngx_str_t)ngx_create_str(
        r->pool, 2 * (cloak_IV_BYTES + sizeof(size_t)) + 1);
    ngx_str_t IV_hex = {2 * cloak_IV_BYTES, cloakparams.data};
    ngx_str_t record_hex = {2 * sizeof(size_t),
                            cloakparams.data + IV_hex.len + 1};

    *((size_t *)cloakparams.data) = htonll(ctx->record_bytes);
    ngx_hex_dump(record_hex.data, cloakparams.data, sizeof(size_t));

    ctx->IV_out = (ngx_str_t)ngx_create_str(r->pool, cloak_IV_BYTES);
    RAND_bytes(ctx->IV_out.data, ctx->IV_out.len);
    ngx_hex_dump(IV_hex.data, ctx->IV_out.data, ctx->IV_out.len);
    cloakparams.data[IV_hex.len] = ',';
    */

    ngx_str_t cloakparams =
        (ngx_str_t)ngx_create_str(r->pool, cloak_IV_BYTES + sizeof(size_t));
    *((size_t *)cloakparams.data) = htonll(ctx->record_bytes);
    ctx->IV_out = (ngx_str_t)ngx_create_str(r->pool, cloak_IV_BYTES);
    RAND_bytes(ctx->IV_out.data, ctx->IV_out.len);
    ngx_memcpy(cloakparams.data + sizeof(size_t), ctx->IV_out.data,
               ctx->IV_out.len);

    ngx_str_t cloakparams_hex =
        (ngx_str_t)ngx_create_str(r->pool, 2 * cloakparams.len);
    ngx_hex_dump(cloakparams_hex.data, cloakparams.data, cloakparams.len);

    ctx->leading = cloakparams;
    return cloakparams_hex;
}

static ngx_int_t
ngx_http_cloak_output_header_filter(ngx_http_request_t *r)
{
    if (r->headers_out.status != NGX_HTTP_OK || r != r->main ||
        r->method == NGX_HTTP_OPTIONS)
        return ngx_http_next_output_header_filter(r);

    ngx_http_cloak_loc_conf_t *cloak_conf =
        ngx_http_get_module_loc_conf(r, ngx_http_cloak_module);

    if (cloak_conf->enc_flag != 1 || cloak_conf->sign_flag == 1 ||
        cloak_conf->hello_flag == 1)
        return ngx_http_cloak_output_header_integrity_filter(r);

    // ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
    //               "output header filter called %d\n", r->headers_out.status);

    ngx_http_cloak_request_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_cloak_module);
    if (ctx == NULL)
        return NGX_HTTP_FORBIDDEN; // decryption_handler should have created

    ngx_http_cloak_ms_conf_t *ms_conf =
        ngx_http_get_module_main_conf(r, ngx_http_cloak_module);
    if (ms_conf->record_bytes == NGX_CONF_UNSET_SIZE)
        ms_conf->record_bytes = cloak_record_default_BYTES;
    ctx->record_bytes = ms_conf->record_bytes;

    ctx->leading.len = 0;
    ngx_str_t cloakparams =
        ngx_http_cloak_output_cloakparam(r, ctx); /* set ctx->leading.len */
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    ngx_check(h);
    h->hash = 1; // when it is set to 0, the header will be omitted
    ngx_str_set(&h->key, "cloakparams");
    h->value = cloakparams;

    if (r->headers_out.content_length_n >= 0) {
        off_t len = r->headers_out.content_length_n;
        r->headers_out.content_length_n =
            len + (len / ctx->record_bytes) * cloak_tag_BYTES;
        if (len % ctx->record_bytes)
            r->headers_out.content_length_n += cloak_tag_BYTES;
        r->headers_out.content_length_n += ctx->leading.len;
    }
    // ngx_http_clear_content_length(r);
    // ngx_http_clear_last_modified(r);
    // ngx_http_clear_etag(r);
    // ngx_str_set(type, "application/octet-stream");

    ngx_str_t    name = ngx_string("Set-Cookie");
    ngx_array_t *array = ngx_array_create(r->pool, 10, sizeof(ngx_str_t *));
    ngx_cloak_find_headers(&r->headers_out.headers, &name, array);

    ngx_table_elt_t **elts = array->elts;
    for (ngx_uint_t i = 0; i < array->nelts; i++) {
        ngx_str_t *value = &(elts[i]->value);
        ngx_uint_t lp = 0, rp = 0;
        for (ngx_uint_t p = 0; p < value->len; p++)
            if (value->data[p] == '=')
                lp = p + 1;
            else if (value->data[p] == ';') {
                rp = p;
                break;
            }

        ngx_str_t plain = {rp - lp, value->data + lp},
                  cipher = ngx_create_str(r->pool, rp - lp + cloak_tag_BYTES),
                  tag = {cloak_tag_BYTES, cipher.data + rp - lp};
        cipher.len = rp - lp;
        ngx_encrypt_AES_GCM_256(&cipher, plain, zeroIV, &tag, ctx->K);
        ngx_str_t cookie = ngx_create_str(r->pool, value->len + cipher.len +
                                                       2 * cloak_tag_BYTES);
        ngx_memcpy(cookie.data, value->data, lp);
        ngx_hex_dump(cookie.data + lp, cipher.data, cipher.len + tag.len);
        ngx_memcpy(cookie.data + lp + 2 * (cipher.len + tag.len),
                   value->data + rp, value->len - rp);
        elts[i]->value = cookie;
    }

    return ngx_http_next_output_header_filter(r);
}

static ngx_int_t
ngx_http_cloak_output_integrity_filter(ngx_http_request_t *r, ngx_chain_t *out)
{
    // if (r->headers_out.status != NGX_HTTP_OK || r != r->main)
    //     return ngx_http_next_output_body_filter(r, out);

    ngx_http_cloak_loc_conf_t *cloak_conf =
        ngx_http_get_module_loc_conf(r, ngx_http_cloak_module);

    if (cloak_conf->sign_flag != 1 || cloak_conf->enc_flag == 1 ||
        cloak_conf->hello_flag == 1)
        return ngx_http_next_output_body_filter(r, out);

    ngx_http_cloak_request_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_cloak_module);
    if (ctx == NULL || ctx->type == 3)
        return ngx_http_next_output_body_filter(r, out);

    if (ctx->mdctx == NULL) {
        ngx_check(ctx->mdctx = EVP_MD_CTX_create());
        EVP_DigestInit_ex(ctx->mdctx, EVP_sha256(), NULL);
    }

    ngx_chain_t *last = NULL;
    ngx_chain_t *penult = NULL;

    for_each_buf(cl, out)
    {
        penult = last;
        last = cl;
        const size_t buflen =
            ngx_buf_special(cl->buf) ? 0 : ngx_buf_size(cl->buf);
        EVP_DigestUpdate(ctx->mdctx, cl->buf->pos, buflen);
    }
    if (last && last->buf->last_buf) {
        ngx_http_cloak_ms_conf_t *ms_conf =
            ngx_http_get_module_main_conf(r, ngx_http_cloak_module);
        ngx_http_cloak_state_conf_t *state = ms_conf->state;

        u_int     dgst_len;
        u_char    dgst[EVP_MAX_MD_SIZE];
        ngx_str_t sign = ngx_create_str(r->pool, cloak_sign_BYTES);

        EVP_DigestFinal(ctx->mdctx, dgst, &dgst_len);
        ECDSA_SIG *signature = ECDSA_do_sign(
            dgst, dgst_len,
            (EC_KEY *)EVP_PKEY_get0_EC_KEY(state->dns_private_key));
        sign.len = sigtoraw(sign.data, signature);
        EVP_MD_CTX_free(ctx->mdctx);
        ECDSA_SIG_free(signature);

        char *header = (ctx->type & 1) ? cloak_HTML_integrity_header
                                       : cloak_JS_integrity_header;
        char *footer = (ctx->type & 1) ? cloak_HTML_integrity_footer
                                       : cloak_JS_integrity_footer;
        int   hlen = strlen(header);
        int   flen = strlen(footer);

        ngx_chain_t *final = ngx_alloc_chain_link(r->pool);
        final->buf =
            ngx_create_temp_buf(r->pool, hlen + 2 * cloak_sign_BYTES + flen);
        ngx_memcpy(final->buf->pos, header, hlen);
        u_char *offset =
            ngx_hex_dump(final->buf->pos + hlen, sign.data, sign.len);
        ngx_memcpy(offset, footer, flen);
        final->buf->last = offset + flen;

        if (ngx_buf_special(last->buf)) {
            final->next = last;
            if (penult)
                penult->next = final;
            else
                out = final;
        } else {
            last->buf->last_buf = last->buf->last_in_chain = 0;
            last->next = final;
            final->buf->last_buf = final->buf->last_in_chain = 1;
            final->next = NULL;
            last = final;
        }
    }
    if (last)
        last->buf->last_in_chain = 1;

    return ngx_http_next_output_body_filter(r, out);
}

static ngx_int_t
ngx_cloak_enlarge_buffer_size(ngx_str_t *buf, size_t bufcnt, size_t len,
                              ngx_pool_t *pool)
{
    if (bufcnt + len > buf->len) {
        ngx_str_t temp =
            (ngx_str_t)ngx_create_str(pool, max(2 * buf->len, bufcnt + len));
        ngx_memcpy(temp.data, buf->data, bufcnt);
        (*buf) = temp;
        return 1;
    }
    return 0;
}

static ngx_int_t
ngx_http_cloak_init_AES_GCM_256(ngx_http_cloak_request_ctx_t *ctx,
                                ngx_str_t                    *iv)
{
    ngx_check(ctx->evp = EVP_CIPHER_CTX_new());
    ngx_check(
        EVP_EncryptInit_ex(ctx->evp, EVP_aes_256_gcm(), NULL, NULL, NULL));
    ngx_check(
        EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_GCM_SET_IVLEN, iv->len, NULL));
    ngx_check(EVP_EncryptInit_ex(ctx->evp, NULL, NULL, ctx->K.data, iv->data));
    return NGX_OK;
}

static int
ngx_http_cloak_final_AES_GCM_256(ngx_http_cloak_request_ctx_t *ctx, u_char *out)
{
    if (out == NULL) {
        EVP_CIPHER_CTX_free(ctx->evp);
        ctx->evp = NULL;
        return 0;
    }
    int outl = 0;
    ngx_check(EVP_EncryptFinal_ex(ctx->evp, out, &outl));
    ngx_check(EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_GCM_GET_TAG,
                                  cloak_tag_BYTES, out + outl));
    EVP_CIPHER_CTX_free(ctx->evp);
    ctx->evp = NULL;
    return outl + cloak_tag_BYTES;
}

static ngx_int_t
ngx_http_cloak_output_encryption_filter(ngx_http_request_t *r, ngx_chain_t *out)
{
    if (r->headers_out.status != NGX_HTTP_OK || r != r->main ||
        r->method == NGX_HTTP_OPTIONS || out == NULL)
        return ngx_http_next_output_body_filter(r, out);

    ngx_http_cloak_loc_conf_t *cloak_conf =
        ngx_http_get_module_loc_conf(r, ngx_http_cloak_module);

    if (cloak_conf->enc_flag != 1 || cloak_conf->sign_flag == 1 ||
        cloak_conf->hello_flag == 1)
        return ngx_http_cloak_output_integrity_filter(r, out);

    // ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
    //               "output body filter called! %d \n", r->headers_out.status);

    ngx_http_cloak_request_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_cloak_module);
    if (ctx == NULL)
        return NGX_HTTP_FORBIDDEN;
    if (ctx->evp == NULL) {
        ngx_http_cloak_init_AES_GCM_256(ctx, &(ctx->IV_out));
        if (ctx->buffer.data == NULL)
            ctx->buffer =
                (ngx_str_t)ngx_create_str(r->pool, cloak_initial_buffer_BYTES);
        ngx_memcpy(ctx->buffer.data, ctx->leading.data, ctx->leading.len);
        ctx->count = ctx->leading.len; /* not zero after request handler */
        ctx->enc_bytes = 0; /* enc_bytes is zero by default and leading bytes
                               should not be encrypted */
    }

    ngx_chain_t *last = NULL;
    ngx_chain_t *penult = NULL;
    int outl = 0; /* outl should be equal to len after EVP_EncryptUpdate */
    ngx_str_t *cipher = &(ctx->buffer);

    for_each_buf(cl, out)
    {
        penult = last;
        last = cl;
        const size_t len = ngx_buf_special(cl->buf) ? 0 : ngx_buf_size(cl->buf);
        if (len == 0)
            continue;
        size_t used = 0;
        while (used < len) {
            size_t remain_bytes =
                min(ctx->record_bytes - ctx->enc_bytes, len - used);
            ngx_cloak_enlarge_buffer_size(cipher, ctx->count, remain_bytes,
                                          r->pool);
            ngx_check(EVP_EncryptUpdate(ctx->evp, cipher->data + ctx->count,
                                        &outl, cl->buf->pos + used,
                                        remain_bytes));
            used += remain_bytes;
            ctx->enc_bytes += remain_bytes;
            ctx->count += outl;
            if (ctx->enc_bytes == ctx->record_bytes) {
                ngx_cloak_enlarge_buffer_size(
                    cipher, ctx->count,
                    cloak_max_padding_BYTES + cloak_tag_BYTES, r->pool);
                ctx->count += ngx_http_cloak_final_AES_GCM_256(
                    ctx, cipher->data + ctx->count);
                ngx_http_cloak_init_AES_GCM_256(ctx, &(ctx->IV_out));
                ctx->enc_bytes = 0;
            }
        }
        ngx_memcpy(cl->buf->pos, cipher->data, len);
        ngx_memmove(cipher->data, cipher->data + len, ctx->count - len);
        ctx->count -= len;
    }

    /*
    if (ctx->count >= cloak_initial_buffer_BYTES) {
    }
    */

    if (last && last->buf->last_buf) {
        if (ctx->enc_bytes > 0) {
            ngx_cloak_enlarge_buffer_size(
                cipher, ctx->count, cloak_max_padding_BYTES + cloak_tag_BYTES,
                r->pool);
            ctx->count += ngx_http_cloak_final_AES_GCM_256(ctx, cipher->data +
                                                                    ctx->count);
        } else
            ngx_http_cloak_final_AES_GCM_256(ctx, NULL);

        ngx_chain_t *final = ngx_alloc_chain_link(r->pool);
        final->buf = ngx_create_temp_buf(r->pool, ctx->count);
        final->buf->tag =
            (ngx_buf_tag_t)&ngx_http_cloak_output_encryption_filter;
        final->buf->recycled = 1;
        ngx_memcpy(final->buf->pos, cipher->data, ctx->count);
        final->buf->last = final->buf->pos + ctx->count;
        ctx->count = 0;

        if (ngx_buf_special(last->buf)) { /* maybe a special empty buf */
            final->next = last;
            if (penult)
                penult->next = final;
            else
                out = final;
        } else {
            last->buf->last_buf = last->buf->last_in_chain = 0;
            last->next = final;
            final->buf->last_buf = final->buf->last_in_chain = 1;
            final->next = NULL;
            last = final;
        }
    }
    if (last)
        last->buf->last_in_chain = 1;


    return ngx_http_next_output_body_filter(r, out);
}
