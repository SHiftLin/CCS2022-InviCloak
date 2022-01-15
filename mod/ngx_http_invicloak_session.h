#pragma once
#include "ngx_http_invicloak_util.h"


#define cloak_sessionID_BYTES 32U
#define cloak_requestID_timeout 120U
#define cloak_requestID_count 256U
#define cloak_requestID_count_BYTES (cloak_requestID_count >> 3)
#define cloak_session_timeout 30 * 86400


typedef struct {
    ngx_rbtree_t     rbtree;
    ngx_slab_pool_t *shpool;
} ngx_http_cloak_sessions_t;

typedef struct {
    ngx_str_node_t    node; // must be at the first one
    ngx_str_t         K;
    ngx_cloak_queue_t queue;
} ngx_cloak_session_node_t;


static ngx_int_t
ngx_http_cloak_init_sessions(ngx_slab_pool_t *           shpool,
                             ngx_http_cloak_sessions_t **sessions)
{
    ngx_http_cloak_sessions_t *s =
        ngx_slab_calloc(shpool, sizeof(ngx_http_cloak_sessions_t));
    ngx_check(s);
    ngx_rbtree_node_t *sentinel =
        ngx_slab_calloc(shpool, sizeof(ngx_rbtree_node_t));
    ngx_check(sentinel);

    ngx_rbtree_init(&(s->rbtree), sentinel, ngx_str_rbtree_insert_value);
    s->shpool = shpool;

    (*sessions) = s;
    return NGX_OK;
}

static void
ngx_http_cloak_clear_rbtree(ngx_http_cloak_sessions_t *sessions)
{
    // TODO: traverse from the smallest key to remove expired nodes
    return;
}

#define alloc_and_clear(p, sessions, size)                                     \
    p = ngx_slab_calloc(sessions->shpool, size);                               \
    if (p == NULL) {                                                           \
        ngx_http_cloak_clear_rbtree(sessions);                                 \
        p = ngx_slab_calloc(sessions->shpool, size);                           \
        if (p == NULL)                                                         \
            return NGX_ERROR;                                                  \
    }

ngx_cloak_session_node_t *
ngx_http_cloak_session_lookup(ngx_http_cloak_sessions_t *sessions,
                              ngx_str_t *                sID)
{
    ngx_shmtx_lock(&sessions->shpool->mutex);
    ngx_cloak_session_node_t *snode =
        (ngx_cloak_session_node_t *)ngx_str_rbtree_lookup(
            &(sessions->rbtree), sID, *((u_int *)(sID->data)));
    ngx_shmtx_unlock(&sessions->shpool->mutex);
    return snode;
}

static ngx_int_t // sID should has been alloced
ngx_http_cloak_get_sessionID(ngx_str_t sID, ngx_str_t K,
                             ngx_http_cloak_sessions_t *sessions)
{
    time_t t;
    u_int *timestamp = (u_int *)sID.data;
    do {
        t = time(NULL);
        (*timestamp) = (u_int)t;
        ngx_check(
            RAND_bytes(sID.data + sizeof(u_int), sID.len - sizeof(u_int)));

        ngx_str_node_t *res =
            (ngx_str_node_t *)ngx_http_cloak_session_lookup(sessions, &sID);
        if (res == NULL)
            break;
    } while (true); // read only

    void * mem;
    size_t msize =
        sizeof(ngx_cloak_session_node_t) +
        sizeof(u_char) * (sID.len + K.len + 2 * cloak_requestID_count_BYTES);
    alloc_and_clear(mem, sessions, msize);

    ngx_cloak_session_node_t *snode = mem;
    snode->node.node.key = *timestamp;

    snode->node.str.len = sID.len;
    snode->node.str.data = (u_char *)mem + sizeof(ngx_cloak_session_node_t);
    ngx_memcpy(snode->node.str.data, sID.data, sID.len);

    snode->K.len = K.len;
    snode->K.data = (u_char *)(snode->node.str.data) + sID.len;
    ngx_memcpy(snode->K.data, K.data, K.len);

    snode->queue.len = 2 * cloak_requestID_count_BYTES;
    snode->queue.q = (u_char *)(snode->K.data) + K.len;
    // ngx_queue_init(&(snode->queue.q));

    ngx_shmtx_lock(&sessions->shpool->mutex);
    ngx_rbtree_insert(&sessions->rbtree, (ngx_rbtree_node_t *)snode);
    ngx_shmtx_unlock(&sessions->shpool->mutex);
    return NGX_OK;
}

/*
static void
ngx_http_cloak_clear_queue(ngx_slab_pool_t *shpool, ngx_cloak_queue_t *queue,
                           u_int now)
{
    ngx_cloak_queue_t *elt;
    ngx_queue_t *      h = &queue->q;
    for (ngx_queue_t *p = ngx_queue_head(h); p != ngx_queue_sentinel(h);
         p = p->next) {
        elt = ngx_queue_data(p, ngx_cloak_queue_t, q);
        if (elt->timestamp + cloak_requestID_timeout < now) {
            ngx_queue_remove(&(elt->q));
            ngx_slab_free_locked(shpool, elt);
        } else
            break; // must make sure the rID is pushed in order of time
    }
}
*/

static void
ngx_http_cloak_clear_queue(ngx_cloak_queue_t *queue)
{
    while (!ngx_cloak_queue_empty(queue) &&
           ngx_cloak_queue_front(queue) == UCHAR_MAX) {
        ngx_cloak_queue_pop(queue);
    }
}

static bool
ngx_http_cloak_verify_request_session(ngx_http_cloak_sessions_t *sessions,
                                      ngx_cloak_session_node_t * snode,
                                      u_int now, u_int rID)
{
    ngx_shmtx_lock(&sessions->shpool->mutex);

    bool flag = false;
    do {
        ngx_http_cloak_clear_queue(&snode->queue);

        ngx_cloak_queue_loc_t loc = ngx_cloak_queue_idtoloc(&snode->queue, rID);
        if (ngx_cloak_queue_isset(&snode->queue, &loc))
            break;
        if (!ngx_cloak_queue_set(&snode->queue, &loc))
            break;
        flag = true;
    } while (false);

    flag = true; // only for server experiments, should be deleted
    ngx_shmtx_unlock(&sessions->shpool->mutex);
    return flag;

    /*
    ngx_cloak_session_node_t *snode =
        (ngx_cloak_session_node_t *)ngx_str_rbtree_lookup(
            &(sessions->rbtree), sID, *((u_int *)(sID->data)));
    if (snode == NULL) {
        ngx_shmtx_unlock(&sessions->shpool->mutex);
        return false;
    }
    ngx_cloak_queue_t *elt;
    ngx_queue_t *      h = &snode->queue.q;
    for (ngx_queue_t *p = ngx_queue_head(h); p != ngx_queue_sentinel(h);
         p = p->next) {
        elt = ngx_queue_data(p, ngx_cloak_queue_t, q);
        if (elt->rID == rID) {
            ngx_shmtx_unlock(&sessions->shpool->mutex);
            // return false;
            return true;
        }
    }

    ngx_cloak_queue_t *q =
        ngx_slab_calloc_locked(sessions->shpool, sizeof(ngx_cloak_queue_t));
    if (q == NULL) {
        ngx_shmtx_unlock(&sessions->shpool->mutex);
        return false;
    }
    q->timestamp = now;
    q->rID = rID;
    ngx_queue_insert_tail(h, &(q->q));
    */
}
