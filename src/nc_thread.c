#include <nc_core.h>

/* Which thread we assigned a connection to most recently. */
static int last_thread = -1;
static int num_threads;


#define SU_PER_ALLOC 64

/* Free list of swapunit structs */
static struct swapunit *sui_freelist;
static pthread_mutex_t sui_freelist_lock;

/*
 * Returns a fresh connection swapunit queue item.
 */
struct swapunit *
sui_new(void) {
    struct swapunit *item = NULL;
    pthread_mutex_lock(&sui_freelist_lock);
    if (sui_freelist) {
        item = sui_freelist;
        sui_freelist = item->next;
    }
    pthread_mutex_unlock(&sui_freelist_lock);

    if (NULL == item) {
        int i;

        /* Allocate a bunch of items at once to reduce fragmentation */
        item = nc_alloc(sizeof(struct swapunit) * SU_PER_ALLOC);
        if (NULL == item) {
            return NULL;
        }

        /*
         * Link together all the new items except the first one
         * (which we'll return to the caller) for placement on
         * the freelist.
         */
        for (i = 2; i < SU_PER_ALLOC; i++)
            item[i - 1].next = &item[i];

        pthread_mutex_lock(&sui_freelist_lock);
        item[SU_PER_ALLOC - 1].next = sui_freelist;
        sui_freelist = &item[1];
        pthread_mutex_unlock(&sui_freelist_lock);
    }

    STAILQ_NEXT(item, nextsu) = NULL;

    return item;
}


/*
 * Frees a connection swapunit queue item (adds it to the freelist.)
 */
void 
sui_free(struct swapunit *item) {
    pthread_mutex_lock(&sui_freelist_lock);
    item->next = sui_freelist;
    sui_freelist = item;
    pthread_mutex_unlock(&sui_freelist_lock);
}

int
thread_data_init(struct thread_data *tdata)
{
    rstatus_t status;
    
    if (tdata == NULL) {
        return NC_ERROR;
    }

    tdata->id = 0;
    tdata->thread_id = 0;
    tdata->socketpairs[0] = -1;
    tdata->socketpairs[1] = -1;
    tdata->nci = NULL;
    tdata->ctx = NULL;
    tdata->notice = NULL;
    STAILQ_INIT(&tdata->sul);
    pthread_mutex_init(&tdata->sullock, NULL);
    tdata->tstats = NULL;

    status = socketpair(AF_LOCAL, SOCK_STREAM, 0, tdata->socketpairs);
    if (status < 0) {
        log_error("create socketpairs failed: %s", strerror(errno));
        return NC_ERROR;
    }

    status = nc_set_nonblocking(tdata->socketpairs[0]);
    if (status < 0) {
        log_error("set socketpairs[0] %d nonblocking failed: %s", 
            tdata->socketpairs[0], strerror(errno));
        close(tdata->socketpairs[0]);
        tdata->socketpairs[0] = -1;
        close(tdata->socketpairs[1]);
        tdata->socketpairs[1] = -1;
        return NC_ERROR;
    }

    status = nc_set_nonblocking(tdata->socketpairs[1]);
    if (status < 0) {
        log_error("set socketpairs[1] %d nonblocking failed: %s", 
            tdata->socketpairs[1], strerror(errno));
        close(tdata->socketpairs[0]);
        tdata->socketpairs[0] = -1;
        close(tdata->socketpairs[1]);
        tdata->socketpairs[1] = -1;
        return NC_ERROR;
    }

    return NC_OK;
}

void
thread_data_deinit(struct thread_data *tdata)
{
    if (tdata == NULL) {
        return;
    }

    tdata->id = 0;
    tdata->thread_id = 0;
    tdata->nci = NULL;
    tdata->ctx = NULL;

    if (tdata->socketpairs[0] > 0){
        close(tdata->socketpairs[0]);
        tdata->socketpairs[0] = -1;
    }
    if (tdata->socketpairs[1] > 0){
        close(tdata->socketpairs[1]);
        tdata->socketpairs[1] = -1;
    }

    if (tdata->notice != NULL) {
        nc_free(tdata->notice);
        tdata->notice = NULL;
    }
}

struct swapunit *
sul_pop(struct thread_data *tdata)
{
    struct swapunit *su = NULL;

    pthread_mutex_lock(&tdata->sullock);
    if (!STAILQ_EMPTY(&tdata->sul)) {
        su = STAILQ_FIRST(&tdata->sul);
        STAILQ_REMOVE_HEAD(&tdata->sul, nextsu);
    }
    pthread_mutex_unlock(&tdata->sullock);
    return su;
}

void
sul_push(struct thread_data *tdata, struct swapunit *su)
{
    ASSERT(STAILQ_NEXT(su, nextsu) == NULL);
    
    pthread_mutex_lock(&tdata->sullock);
    STAILQ_INSERT_TAIL(&tdata->sul, su, nextsu);
    pthread_mutex_unlock(&tdata->sullock);
}

void
dispatch_conn_new(int sd, uint32_t pool_id, struct array *workers)
{
    struct swapunit *su = sui_new();
    char buf[1];

    if (su == NULL) {
        close(sd);
        /* given that malloc failed this may also fail, but let's try */
        log_error("Failed to allocate memory for connection object\n");
        return ;
    }
    
    int tid = (last_thread + 1) % num_threads;

    struct thread_data *worker = array_get(workers, (uint32_t)tid);

    last_thread = tid;

    su->sd = sd;
    su->pool_id = pool_id;

    sul_push(worker, su);

    buf[0] = 'c';
    if (write(worker->socketpairs[0], buf, 1) != 1) {
        log_error("Notice the worker failed.");
    }
}

static int
setup_worker(struct thread_data *worker)
{
    struct conn *notice;

    notice = conn_get_notice(worker);
    if (notice == NULL) {
        return NC_ENOMEM;
    }

    event_add_conn(worker->ctx->evb, notice);
    event_del_out(worker->ctx->evb, notice);

    return NC_OK;
}

static rstatus_t
client_accept(struct context *ctx, struct conn *notice)
{
    rstatus_t status;
    char buf[1];
    int sd;
    struct conn *c;
    struct swapunit *su;
    struct server_pool *sp;
    struct thread_data *tdata = notice->owner;

    ASSERT(notice->sd == tdata->socketpairs[1]);

    if (nc_read(notice->sd, buf, 1) != 1) {
        log_debug(LOG_DEBUG, "can't read from thread(id:%d) socketpairs[1] %d", 
            tdata->id, notice->sd);
        buf[0] = 'c';
        notice->recv_ready = 0;
    }

    switch (buf[0]) {
    case 'c':
        su = sul_pop(tdata);
        if (su == NULL) {
            return NC_OK;
        }
        sd = su->sd;
        sp = array_get(&ctx->pool, su->pool_id);
        sui_free(su);
        c = conn_get(sp, true, sp->redis ? NC_SOURCE_TYPE_REDIS : NC_SOURCE_TYPE_MC, ctx->cb);
        if (c == NULL) {
            log_error("get conn for c %d from pool %.*s failed: %s", 
                sd, sp->name.len, sp->name.data, strerror(errno));
            status = close(sd);
            if (status < 0) {
                log_error("close c %d failed, ignored: %s", sd, strerror(errno));
            }
            return NC_ENOMEM;
        }
        c->sd = sd;
    
        stats_pool_incr(ctx, c->owner, client_connections);
    
        status = nc_set_nonblocking(c->sd);
        if (status < 0) {
            log_error("set nonblock on c %d from pool %.*s failed: %s", 
                c->sd, sp->name.len, sp->name.data, strerror(errno));
            c->close(ctx, c);
            return status;
        }

        if (sp->tcpkeepalive) {
			status = nc_set_tcpkeepalive(c->sd, sp->tcpkeepidle, 
				sp->tcpkeepintvl, sp->tcpkeepcnt);
			if (status != NC_OK) {
				log_warn("set tcpkeepalive on c %d from pool %.*s failed, ignored: %s",
				    c->sd, sp->name.len, sp->name.data, strerror(errno));
			}
		}
    
        if (sp->info.family == AF_INET || sp->info.family == AF_INET6) {
            status = nc_set_tcpnodelay(c->sd);
            if (status < 0) {
                log_warn("set tcpnodelay on c %d from pool %.*s failed, ignored: %s",
                    c->sd, sp->name.len, sp->name.data, strerror(errno));
            }
        }
    
        status = event_add_conn(ctx->evb, c);
        if (status < 0) {
            log_error("event add conn from pool %.*s failed: %s", 
                sp->name.len, sp->name.data, strerror(errno));
            c->close(ctx, c);
            return status;
        }
    
        log_debug(LOG_DEBUG, "accepted c %d on pool %.*s from '%s'", 
            c->sd, sp->name.len, sp->name.data, nc_unresolve_peer_desc(c->sd));
        break;
    default:
        log_error("read error char '%c' from thread(id:%d) socketpairs[1] %d", 
            buf[0], tdata->id, notice->sd);
        break;
    }

    return NC_OK;
}

rstatus_t
notice_recv(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    ASSERT(conn->notice);
    ASSERT(!conn->proxy && !conn->client);
    ASSERT(conn->recv_active);

    conn->recv_ready = 1;
    do {
        status = client_accept(ctx, conn);
        if (status != NC_OK) {
            return status;
        }
    } while (conn->recv_ready);

    return NC_OK;
}

void
notice_ref(struct conn *conn, void *owner)
{
    struct thread_data *tdata = owner;

    ASSERT(conn->notice);
    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->owner == NULL);

    tdata->notice = conn;

    /* owner of the proxy connection is the server pool */
    conn->owner = owner;
    
    conn->sd = tdata->socketpairs[1];

    log_debug(LOG_VVERB, "ref conn %p owner %p for thread %d", conn,
        tdata, tdata->id);
}

void
notice_unref(struct conn *conn)
{
    struct thread_data *tdata;

    ASSERT(conn->notice);
    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->owner != NULL);

    tdata = conn->owner;
    conn->owner = NULL;

    tdata->notice = NULL;

    log_debug(LOG_VVERB, "unref conn %p owner %p from thread %d", conn,
        tdata, tdata->id);
}

int
master_run(struct instance *nci, struct array *workers)
{
    rstatus_t status;
    struct context *ctx;

    log_debug(LOG_DEBUG, "master running");

    sui_freelist = NULL;
    pthread_mutex_init(&sui_freelist_lock, NULL);

    ctx = core_ctx_create(nci, NC_CONTEXT_ROLE_MASTER);
    if (ctx == NULL) {
        return NC_ERROR;
    }

    ctx->workers = workers;
    num_threads = (int)array_n(workers);

    /*
     * Get rlimit and calculate max client connections after we have
     * calculated max server connections
     */
    status = core_calc_connections(ctx);
    if (status != NC_OK) {
        core_ctx_destroy(ctx);
        return NC_ERROR;
    }

    /* run rabbit run */
    for (;;) {
        status = core_loop(ctx);
        if (status != NC_OK) {
            break;
        }
    }

    core_ctx_destroy(ctx);
    
    return NC_OK;
}

void *worker_thread_run(void *args)
{
    rstatus_t status;
    struct thread_data *worker = args;

    worker->ctx = core_ctx_create(worker->nci, NC_CONTEXT_ROLE_WORKER);
    if (worker->ctx == NULL) {
        return NULL;
    }

    pthread_mutex_init(&worker->ctx->statslock, NULL);

    status = setup_worker(worker);
    if (status != NC_OK) {
        core_ctx_destroy(worker->ctx);
        return NULL;
    }

    /* run rabbit run */
    for (;;) {
        status = core_loop(worker->ctx);
        if (status != NC_OK) {
            break;
        }
    }

    core_ctx_destroy(worker->ctx);

    return NULL;
}

