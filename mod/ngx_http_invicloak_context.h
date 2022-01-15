#pragma once
#include "ngx_http_invicloak_crypto.h"
#include "ngx_http_invicloak_session.h"
#include "ngx_http_invicloak_util.h"

typedef struct {
    ngx_http_cloak_sessions_t *sessions;
} ngx_http_cloak_shds_t;

typedef struct {
    ngx_slab_pool_t *      shpool;
    ngx_http_cloak_shds_t *shds;
    ngx_str_t              stek;
    EVP_PKEY *             dns_private_key;
} ngx_http_cloak_state_conf_t;

typedef struct {
    ngx_http_cloak_state_conf_t *state;
    size_t                       record_bytes;
} ngx_http_cloak_ms_conf_t;

typedef struct {
    ngx_int_t hello_flag;
    ngx_int_t enc_flag;
    ngx_int_t sign_flag;
    ngx_int_t args_index;
} ngx_http_cloak_loc_conf_t;

typedef struct {
    u_int     done : 1; /* will only be used by clienthello or decryption */
    u_int     type : 2;
    u_int     remain : 1;
    u_char    remain_char;
    u_int     tag_in : 1;
    size_t    count;
    ngx_str_t K;
    ngx_str_t sID;
    ngx_str_t IV_in;
    ngx_str_t IV_out;
    ngx_str_t buffer; /* use count for storing used size in output */
    ngx_str_t leading;
    size_t    enc_bytes;
    size_t    record_bytes; /* copy from ngx_http_cloak_ms_conf_t */
    ngx_http_cloak_sessions_t *sessions;
    ngx_cloak_session_node_t * snode;
    EVP_MD_CTX *               mdctx;
    EVP_CIPHER_CTX *           evp;
} ngx_http_cloak_request_ctx_t;


extern ngx_module_t ngx_http_cloak_module;
static ngx_int_t
ngx_http_cloak_request_decryption_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cloak_request_decryption_filter(ngx_http_request_t *r,
                                                          ngx_chain_t *in);
static ngx_int_t ngx_http_cloak_clienthello_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cloak_output_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_cloak_output_encryption_filter(ngx_http_request_t *r,
                                                         ngx_chain_t *out);

static ngx_http_cloak_state_conf_t *
ngx_http_cloak_create_state(ngx_conf_t *cf)
{
    ngx_http_cloak_state_conf_t *state =
        (ngx_http_cloak_state_conf_t *)ngx_palloc(
            cf->pool, sizeof(ngx_http_cloak_state_conf_t));
    if (state == NULL)
        return NULL;

    state->shpool = NGX_CONF_UNSET_PTR;
    state->shds = NGX_CONF_UNSET_PTR;
    state->dns_private_key = NGX_CONF_UNSET_PTR;
    state->stek.data = NGX_CONF_UNSET_PTR;
    state->stek.len = NGX_CONF_UNSET_SIZE;

    return state;
}

static char *
ngx_http_cloak_merge_state(ngx_http_cloak_state_conf_t *p,
                           ngx_http_cloak_state_conf_t *c)
{
    ngx_conf_merge_ptr_value(c->shpool, p->shpool, NULL);
    ngx_conf_merge_ptr_value(c->shds, p->shds, NULL);
    ngx_conf_merge_ptr_value(c->stek.data, p->stek.data, NULL);
    ngx_conf_merge_size_value(c->stek.len, p->stek.len, 0);
    ngx_conf_merge_ptr_value(c->dns_private_key, p->dns_private_key, NULL);
    return NGX_CONF_OK;
}

static void *
ngx_http_cloak_create_ms_conf(ngx_conf_t *cf)
{
    ngx_http_cloak_ms_conf_t *ms_conf = (ngx_http_cloak_ms_conf_t *)ngx_pcalloc(
        cf->pool, sizeof(ngx_http_cloak_ms_conf_t));
    if (ms_conf == NULL)
        return NULL;

    ms_conf->state = ngx_http_cloak_create_state(cf);
    if (ms_conf->state == NULL)
        return NULL;
    ms_conf->record_bytes = NGX_CONF_UNSET_SIZE;
    return ms_conf;
}

static char *
ngx_http_cloak_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}

static char *
ngx_http_cloak_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cloak_ms_conf_t *p = parent;
    ngx_http_cloak_ms_conf_t *c = child;

    return ngx_http_cloak_merge_state(p->state, c->state);
}

static void *
ngx_http_cloak_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cloak_loc_conf_t *local_conf =
        (ngx_http_cloak_loc_conf_t *)ngx_pcalloc(
            cf->pool, sizeof(ngx_http_cloak_loc_conf_t));
    if (local_conf == NULL)
        return NULL;

    local_conf->hello_flag = NGX_CONF_UNSET;
    local_conf->enc_flag = NGX_CONF_UNSET;
    local_conf->sign_flag = NGX_CONF_UNSET;
    local_conf->args_index = 0;

    return local_conf;
}

static ngx_int_t
ngx_http_cloak_init_shds(ngx_slab_pool_t *shpool, ngx_http_cloak_shds_t *shds)
{
    return ngx_http_cloak_init_sessions(shpool, &(shds->sessions));
}

static ngx_int_t
ngx_http_cloak_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_cloak_state_conf_t *octx = data;
    ngx_http_cloak_state_conf_t *ctx = shm_zone->data;

    if (octx) {
        ctx->shds = octx->shds;
        ctx->shpool = octx->shpool;
        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    if (shm_zone->shm.exists) {
        ctx->shds = ctx->shpool->data;
        return NGX_OK;
    }
    ctx->shds = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_cloak_shds_t));
    ngx_check(ctx->shds);
    ngx_check_ok(ngx_http_cloak_init_shds(ctx->shpool, ctx->shds));

    return NGX_OK;
}

static char *
ngx_conf_set_cloakstate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cloak_ms_conf_t *   ms_conf = (ngx_http_cloak_ms_conf_t *)conf;
    ngx_http_cloak_state_conf_t *state = ms_conf->state;
    ngx_str_t *                  value = cf->args->elts;
    size_t                       max_size = 1 << 12;

    ngx_str_t name = value[1];
    size_t    size = ngx_atoi(value[2].data, value[2].len) * 1024;

    ngx_str_t key_pem = ngx_read_whole_file(cf->pool, value[3], max_size);
    state->dns_private_key = ngx_import_crypto_key(key_pem, true);

    if (cf->args->nelts >= 5)
        state->stek = ngx_read_whole_file(cf->pool, value[4], cloak_stek_BYTES);
    else {
        state->stek = (ngx_str_t)ngx_create_str(cf->pool, cloak_stek_BYTES);
        if (!RAND_bytes(state->stek.data, state->stek.len))
            return NGX_CONF_ERROR;
    }

    ngx_shm_zone_t *shm_zone =
        ngx_shared_memory_add(cf, &name, size, &ngx_http_cloak_module);
    shm_zone->init = ngx_http_cloak_init_zone;
    shm_zone->data = state;
    return NGX_CONF_OK;
}

static char *
ngx_conf_set_clienthello(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    ngx_http_core_loc_conf_t *clcf =
        (ngx_http_core_loc_conf_t *)ngx_http_conf_get_module_loc_conf(
            cf, ngx_http_core_module);
    clcf->handler = ngx_http_cloak_clienthello_handler;

    return rv;
}

static char *
ngx_conf_set_cloakenc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cloak_loc_conf_t *local_conf = (ngx_http_cloak_loc_conf_t *)conf;

    char *rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    ngx_str_t args = ngx_string("args");
    local_conf->args_index = ngx_http_get_variable_index(cf, &args);

    return rv;
}


static ngx_str_t zeroIV;

static ngx_int_t
ngx_http_cloak_pre_conf_init(ngx_conf_t *cf)
{
    zeroIV = (ngx_str_t)ngx_create_str(cf->pool, cloak_IV_BYTES);
    return NGX_OK;
}

static ngx_http_output_header_filter_pt ngx_http_next_output_header_filter;
static ngx_http_output_body_filter_pt   ngx_http_next_output_body_filter;
static ngx_http_request_body_filter_pt  ngx_http_next_request_body_filter;

static ngx_int_t
ngx_http_cloak_post_conf_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *      h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL)
        return NGX_ERROR;
    *h = ngx_http_cloak_request_decryption_handler;

    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_cloak_request_decryption_filter;

    ngx_http_next_output_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_cloak_output_header_filter;

    ngx_http_next_output_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_cloak_output_encryption_filter;

    return NGX_OK;
}
