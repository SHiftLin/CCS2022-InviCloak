#pragma once
#include <assert.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdbool.h>
#include <time.h>


#define cloak_initial_buffer_BYTES (64 * 1024) /* at least: pad tag */

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

#define ngx_create_str(pool, size)                                             \
    {                                                                          \
        size, (u_char *)ngx_pcalloc(pool, (size) * sizeof(u_char))             \
    }

#define ngx_create_request_ctx(ctx, r)                                         \
    if (ctx == NULL) {                                                         \
        ctx = (ngx_http_cloak_request_ctx_t *)ngx_pcalloc(                     \
            (r)->pool, sizeof(ngx_http_cloak_request_ctx_t));                  \
        if (ctx == NULL)                                                       \
            return NGX_ERROR;                                                  \
        ngx_http_set_ctx((r), ctx, ngx_http_cloak_module);                     \
    }

#define ngx_strequal(s1, l1, s2, l2)                                           \
    ((l1) == (l2) && ngx_strncmp(s1, s2, l1) == 0)
#define ngx_strcaseequal(s1, l1, s2, l2)                                       \
    ((l1) == (l2) && ngx_strncasecmp(s1, s2, l1) == 0)

#define ngx_get_c_str(pool, dst, src)                                          \
    char *dst = (char *)ngx_palloc(pool, (src.len + 1) * sizeof(char));        \
    ngx_memcpy(dst, src.data, src.len);                                        \
    dst[src.len] = '\0';

#define ngx_hextodec(c)                                                        \
    ((c) <= '9' ? (c) - '0' : ((c) <= 'Z' ? (c) - 'A' + 10 : (c) - 'a' + 10))

#ifndef htonll
#define htonll(x)                                                              \
    ((1 == htonl(1))                                                           \
         ? (x)                                                                 \
         : ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif

#ifndef ntohll
#define ntohll(x)                                                              \
    ((1 == ntohl(1))                                                           \
         ? (x)                                                                 \
         : ((uint64_t)ntohl((x)&0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

#define for_each_buf(cl, bufs)                                                 \
    for (ngx_chain_t *cl = (bufs); cl != NULL; cl = cl->next)
#define for_each_char(ch, buf)                                                 \
    for (u_char *ch = (buf)->pos; ch < (buf)->last; ch++)

#define ngx_check(c)                                                           \
    if (!(c))                                                                  \
    return NGX_ERROR
#define ngx_check_ok(c)                                                        \
    if (c)                                                                     \
    return NGX_ERROR
#define ngx_check_1(c)                                                         \
    if ((c) != 1)                                                              \
        return NGX_ERROR;

#define print_str(p, s, l)                                                     \
    printf(p);                                                                 \
    if (s == NULL)                                                             \
        printf("NULL");                                                        \
    for (char *ch = (char *)(s); ch < (char *)((s) + (l)); ch++)               \
        printf("%c", *ch);                                                     \
    printf("\n");                                                              \
    fflush(stdout)

#define print_bytes(p, s, l)                                                   \
    printf(p);                                                                 \
    if (s == NULL)                                                             \
        printf("NULL");                                                        \
    for (u_char *ch = (u_char *)(s); ch < (u_char *)((s) + (l)); ch++)         \
        printf("%u ", (u_int)*ch);                                             \
    printf("\n");                                                              \
    fflush(stdout)

/*
static ngx_chain_t *
ngx_cloak_copy_chain(ngx_pool_t *pool, ngx_chain_t *in)
{
    ngx_buf_t *  b, *buf;
    ngx_chain_t *out = NULL, *last = NULL, *part = NULL;
    for (; in != NULL; in = in->next) {
        buf = in->buf;
        b = ngx_create_temp_buf(pool, buf->last - buf->pos);
        for (u_char *c = buf->pos; c < buf->last; c++) {
            *(b->last) = *c;
            b->last++;
        }
        part = ngx_alloc_chain_link(pool);
        part->buf = b;
        part->next = NULL;
        if (out == NULL)
            out = part;
        else
            last->next = part;
        last = part;
    }
    last->buf->last_buf = 1;
    last->buf->last_in_chain = 1;
    return out;
}
*/

/*
static void
print_hex(const char *prompt, ngx_str_t str)
{
    printf("%s\"", prompt);
    for (size_t i = 0; i < str.len; i++)
        printf("%u,", str.data[i]);
    printf("\"\n\"");
    for (size_t i = 0; i < str.len; i++)
        printf("%02x", str.data[i]);
    printf("\"\n");
    fflush(stdout);
}
*/

static u_char
ngx_cloak_bitcount8(u_char x)
{
    x = (x & 0x55) + ((x >> 1) & 0x55);
    x = (x & 0x33) + ((x >> 2) & 0x33);
    x = (x & 0x0F) + ((x >> 4) & 0x0F);
    return x;
}

static u_int
ngx_bytestoi(const u_char *bytes) // little end
{
    u_int x = 0;
    for (u_int i = 0; i < sizeof(u_int); i++)
        x += bytes[i] << (i * 8);
    return x;
}

static size_t
ngx_hextobin(unsigned char *dst, unsigned char *src, size_t len)
{
    if (len & 1) // len must be even
        return 0;
    size_t j = 0;
    for (size_t i = 0; i < len; i += 2)
        dst[j++] = ngx_hextodec(src[i]) * 16 + ngx_hextodec(src[i + 1]);
    return j;
}

static ngx_str_t
ngx_read_whole_file(ngx_pool_t *pool, ngx_str_t filename, size_t max_size)
{
    ngx_get_c_str(pool, filename_c, filename);
    ngx_str_t content = ngx_create_str(pool, max_size);
    size_t    offset = 0, ret = 0, chunk_size = 1 << 13;
    int       fd;

    fd = ngx_open_file(filename_c, NGX_FILE_RDONLY, 0, NGX_FILE_DEFAULT_ACCESS);
    assert(fd != -1);
    while ((ret = ngx_read_fd(fd, content.data + offset,
                              min(chunk_size, max_size - offset))))
        offset += ret;
    content.len = offset;

    ngx_close_file(fd);
    return content;
}

static ngx_str_t
ngx_cloak_load_whole_body(ngx_http_request_t *r)
{
    ngx_str_t buf = {0, NULL};
    if (r->request_body->temp_file == NULL) {
        /*
         * The entire request body is available in the list
         * of buffers pointed by r->request_body->bufs.
         */
        size_t len = 0;
        for_each_buf(cl, r->request_body->bufs)
        {
            len += cl->buf->last - cl->buf->pos;
        }

        buf = (ngx_str_t)ngx_create_str(r->pool, len);

        size_t offset = 0;
        for_each_buf(cl, r->request_body->bufs)
        {
            len = (cl->buf->last - cl->buf->pos);
            ngx_memcpy(buf.data + offset, cl->buf->pos, len * sizeof(u_char));
            offset += len;
        }
    } else {
        /* The entire request body is available in the
         * temporary file. */
    }
    return buf;
}

static ngx_str_t
ngx_cloak_get_arg_by_name(ngx_str_t buf, const char *name)
{
    size_t    name_len = ngx_strlen(name);
    bool      flag = false;
    ngx_str_t arg = {0, NULL};
    for (size_t i = 0, j = i; i < buf.len; i = ++j) {
        while (j < buf.len && buf.data[j] != '=')
            j++;
        if (ngx_strequal(name, name_len, buf.data + i, j - i))
            flag = true;
        i = ++j;

        while (j < buf.len && buf.data[j] != '&')
            j++;
        if (flag) {
            arg.len = j - i;
            arg.data = buf.data + i; // what if arg.len==0?
            return arg;
        }
    }
    return arg;
}

static ngx_int_t
ngx_cloak_find_header(ngx_list_t *headers, ngx_str_t *name, ngx_str_t *value)
{
    ngx_list_part_t *part;
    value->data = NULL, value->len = 0;

    /*
    Get the first part of the list. There is usual only one part.
    */
    part = &(headers->part);
    while (part != NULL) {
        ngx_table_elt_t *h = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            if (ngx_strcaseequal(h[i].key.data, h[i].key.len, name->data,
                                 name->len)) {
                *(value) = h[i].value;
                return i;
            }
        }
        part = part->next;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_cloak_find_headers(ngx_list_t *headers, ngx_str_t *name, ngx_array_t *array)
{
    ngx_list_part_t *part;
    /*
    Get the first part of the list. There is usual only one part.
    */
    part = &(headers->part);
    while (part != NULL) {
        ngx_table_elt_t *h = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            if (ngx_strcaseequal(h[i].key.data, h[i].key.len, name->data,
                                 name->len)) {
                ngx_table_elt_t **elt =
                    (ngx_table_elt_t **)ngx_array_push(array);
                *elt = &(h[i]);
            }
        }
        part = part->next;
    }

    return NGX_DECLINED;
}

/*
static ngx_int_t
ngx_cloak_clear_headers(ngx_list_t *headers, ngx_str_t *name)
{
    return 0;
    ngx_list_part_t *part;

    part = &(headers->part);
    while (part != NULL) {
        ngx_table_elt_t *h = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            if (ngx_strcaseequal(h[i].key.data, h[i].key.len, name->data,
                                 name->len)) {
                h[i].key.len = 0;
                h[i].value.len = 0;
            }
        }
        part = part->next;
    }

    return NGX_DECLINED;
}
*/

typedef struct {
    u_int qt, rd, id;
} ngx_cloak_queue_loc_t;

typedef struct {
    u_int                 cnt; // existing bits
    u_int                 lid;
    ngx_cloak_queue_loc_t rid;
    u_int                 head;
    u_int                 len; // bytes
    u_char *              q;
    /*
    u_int     timestamp;
    u_int     rID;
    ngx_queue_t q;
    */
} ngx_cloak_queue_t; // circular bitmap

#define ngx_cloak_uchar_bits (sizeof(u_char) << 3)
#define ngx_cloak_queue_empty(queue) ((queue)->cnt == 0)
#define ngx_cloak_queue_front(queue) ((queue)->q[(queue)->head])
#define ngx_cloak_queue_inc(p, k, qlen)                                        \
    p += k;                                                                    \
    if (p >= qlen)                                                             \
    p -= qlen

static u_int
ngx_cloak_queue_qttoidx(ngx_cloak_queue_t *queue, u_int qt)
{
    u_int idx = queue->head;
    ngx_cloak_queue_inc(idx, qt, queue->len);
    return idx;
}

static ngx_cloak_queue_loc_t
ngx_cloak_queue_idtoloc(ngx_cloak_queue_t *queue, u_int id)
{
    ngx_cloak_queue_loc_t loc;
    loc.qt = (id - queue->lid) / ngx_cloak_uchar_bits;
    loc.rd = (id - queue->lid) % ngx_cloak_uchar_bits;
    loc.id = id;
    return loc;
}

static u_char
ngx_cloak_queue_pop(ngx_cloak_queue_t *queue)
{
    u_char res = queue->q[queue->head];
    queue->q[queue->head] = 0;
    ngx_cloak_queue_inc(queue->head, 1, queue->len);
    queue->lid += ngx_cloak_uchar_bits;
    queue->cnt -= ngx_cloak_bitcount8(res);
    return res;
}

static bool
ngx_cloak_queue_isset(ngx_cloak_queue_t *queue, ngx_cloak_queue_loc_t *loc)
{
    if (loc->qt >= queue->len)
        return false;
    u_int p = ngx_cloak_queue_qttoidx(queue, loc->qt);
    return ((queue->q[p] & (1 << loc->rd)) != 0);
}

static bool
ngx_cloak_queue_set(ngx_cloak_queue_t *queue, ngx_cloak_queue_loc_t *loc)
{
    while ((queue->rid.qt >= queue->len / 2) && loc->qt >= queue->len) {
        ngx_cloak_queue_pop(queue);
        queue->rid.qt--;
        loc->qt--;
    }
    if (loc->qt >= queue->len)
        return false;

    u_int p = ngx_cloak_queue_qttoidx(queue, loc->qt);
    queue->q[p] |= (1 << loc->rd);
    queue->rid = (*loc);
    queue->cnt += 1;
    return true;
}
