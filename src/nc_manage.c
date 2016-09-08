#include <nc_core.h>
#include <nc_proto.h>

static bool
manage_arg0(struct msg *r)
{
	switch (r->type) {
	case MSG_REQ_PROXY_QUIT:
	case MSG_REQ_PROXY_HELP:
    case MSG_REQ_PROXY_STATUS:
	return true;

    default:
        break;
	}
	return false;
}

static bool
manage_arg1(struct msg *r)
{
	switch (r->type) {
    default:
        break;
	}
	return false;
}

static bool
manage_arg2(struct msg *r)
{
	switch (r->type) {
	case MSG_REQ_PROXY_FIND_KEY:
	return true;
        break;
    default:
        break;
	}
	return false;
}

static bool
manage_arg2or3(struct msg *r)
{
	switch (r->type) {
    default:
        break;
	}
	return false;
}

static bool
manage_arg1ormore(struct msg *r)
{
	switch (r->type) {
    case MSG_REQ_PROXY_SLOWLOG:
	return true;
        break;
    default:
        break;
	}
	return false;
}

static bool
manage_arg2ormore(struct msg *r)
{
	switch (r->type) {
    case MSG_REQ_PROXY_FIND_KEYS:
	return true;
        break;
    default:
        break;
	}
	return false;
}

void
manage_parse_req(struct msg *r)
{
    struct mbuf *b;
    uint8_t *p, *m;
    uint8_t ch;
    enum {
        SW_START,
        SW_REQ_TYPE,
        SW_SPACES_BEFORE_KEY,
        SW_KEY,
        SW_SPACES_BEFORE_KEYS,
        SW_CRLF,
        SW_ALMOST_DONE,
        SW_SENTINEL
    } state;

    state = r->state;
    b = STAILQ_LAST(&r->mhdr, mbuf, next);

    ASSERT(r->request);
    ASSERT(r->source_type == NC_SOURCE_TYPE_PROXY);
    ASSERT(state >= SW_START && state < SW_SENTINEL);
    ASSERT(b != NULL);
    ASSERT(b->pos <= b->last);

    /* validate the parsing maker */
    ASSERT(r->pos != NULL);
    ASSERT(r->pos >= b->pos && r->pos <= b->last);

    for (p = r->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        case SW_START:
            if (ch == ' ') {
                break;
            }

            if (!islower(ch)) {
                goto error;
            }

            /* req_start <- p; type_start <- p */
            r->token = p;
            state = SW_REQ_TYPE;

            break;

        case SW_REQ_TYPE:
            if (ch == ' ' || ch == CR) {
                /* type_end = p - 1 */
                m = r->token;
                r->token = NULL;
                r->type = MSG_UNKNOWN;
                r->narg++;

                switch (p - m) {
				case 4:
					if (str4cmp(m, 'q', 'u', 'i', 't')) {
                        r->type = MSG_REQ_PROXY_QUIT;
						r->quit = 1;
                        break;
                    }

					if (str4cmp(m, 'h', 'e', 'l', 'p')) {
                        r->type = MSG_REQ_PROXY_HELP;
						break;
                    }

					break;
					
                case 6:

					if (str6cmp(m, 's', 't', 'a', 't', 'u', 's')) {
                        r->type = MSG_REQ_PROXY_STATUS;
                        break;
                    }
					
                    break;

               case 7:

					if (str7cmp(m, 's', 'l', 'o', 'w', 'l', 'o', 'g')) {
                        r->type = MSG_REQ_PROXY_SLOWLOG;
                        break;
                    }
					
                    break;
                    
                case 8:

					if (str8cmp(m, 'f', 'i', 'n', 'd', '_', 'k', 'e', 'y')) {
                        r->type = MSG_REQ_PROXY_FIND_KEY;
                        break;
                    }
					
                    break;
                    
                case 9:

					if (str9cmp(m, 'f', 'i', 'n', 'd', '_', 'k', 'e', 'y', 's')) {
                        r->type = MSG_REQ_PROXY_FIND_KEYS;
                        break;
                    }
					
                    break;

                }

                switch (r->type) {
                case MSG_REQ_PROXY_FIND_KEY:
                case MSG_REQ_PROXY_FIND_KEYS:
                case MSG_REQ_PROXY_SLOWLOG:
                    if (ch == CR) {
                        goto error;
                    }
                    state = SW_SPACES_BEFORE_KEY;
                    break;

				case MSG_REQ_PROXY_QUIT:
				case MSG_REQ_PROXY_HELP:					
				case MSG_REQ_PROXY_STATUS:
                    p = p - 1; /* go back by 1 byte */
                    state = SW_CRLF;
                    break;

                case MSG_UNKNOWN:
                    goto error;

                default:
                    NOT_REACHED();
                }

            }

            break;

        case SW_SPACES_BEFORE_KEY:
			if (ch == CR) {
				goto error;
			}
            if (ch != ' ') {
                p = p - 1; /* go back by 1 byte */
                r->token = NULL;
                state = SW_KEY;
            }
            break;

        case SW_KEY:
            if (r->token == NULL) {
                r->token = p;
            }
            if (ch == ' ' || ch == CR) {
                struct keypos *kpos;

                if ((size_t)(p - r->token) > mbuf_data_size(r->mb->mbufb)) {
                    log_error("parsed bad req %"PRIu64" of type %d with key "
                              "prefix '%.*s...' and length %d that exceeds "
                              "maximum key length", r->id, r->type, 16,
                              r->token, p - r->token);
                    goto error;
                }

                kpos = array_push(r->keys);
                if (kpos == NULL) {
                    goto enomem;
                }
                kpos->start = r->token;
                kpos->end = p;
				if(kpos->start == kpos->end)
				{
					goto error;
				}

                r->narg++;
                r->token = NULL;

                /* get next state */
                if (manage_arg1(r)) {
                    state = SW_CRLF;
                } else if (manage_arg2(r)) {
                	ASSERT(array_n(r->keys) > 0);
                	if (array_n(r->keys) == 1) {
                		if(ch == CR) {
							goto error;
						} else {
							state = SW_SPACES_BEFORE_KEY;
						}
                	} else if(array_n(r->keys) == 2) {
						state = SW_CRLF;
					} else {
						goto error;
					}
                } else if (manage_arg2or3(r)) {
                	ASSERT(array_n(r->keys) > 0);
                	if (array_n(r->keys) == 1) {
                		if(ch == CR) {
							goto error;
						} else {
							state = SW_SPACES_BEFORE_KEY;
						}
                	} else if(array_n(r->keys) == 2) {
						if (ch == CR) {
							state = SW_CRLF;
						} else {
							state = SW_SPACES_BEFORE_KEYS;
						}			
					} else if(array_n(r->keys) == 3) {
						state = SW_CRLF;
					} else {
						goto error;
					}
                } else if (manage_arg1ormore(r)) {
					ASSERT(array_n(r->keys) > 0);
                    
                	if(ch == CR) {
						state = SW_CRLF;
					} else {
						state = SW_SPACES_BEFORE_KEYS;
					}
                } else if (manage_arg2ormore(r)) {

					ASSERT(array_n(r->keys) > 0);
                	if (array_n(r->keys) == 1) {
                		if(ch == CR) {
							goto error;
						} else {
							state = SW_SPACES_BEFORE_KEY;
						}
                	} else {
						state = SW_SPACES_BEFORE_KEYS;
					}
                } else {
                    goto error;
                }
                
				if (ch == CR) {
					p = p - 1;
				}
            }

            break;

        case SW_SPACES_BEFORE_KEYS:
            ASSERT(manage_arg1ormore(r) || manage_arg2ormore(r) || manage_arg2or3(r));
            switch (ch) {
            case ' ':
                break;

            case CR:
                state = SW_ALMOST_DONE;
                break;

            default:
                r->token = NULL;
                p = p - 1; /* go back by 1 byte */
                state = SW_KEY;
            }

            break;
    
        case SW_CRLF:
            switch (ch) {
            case ' ':
                break;

            case CR:
                state = SW_ALMOST_DONE;
                break;

            default:
                goto error;
            }

            break;

        case SW_ALMOST_DONE:
            switch (ch) {
            case LF:
                /* req_end <- p */
                goto done;

            default:
                goto error;
            }

            break;

        case SW_SENTINEL:
        default:
            NOT_REACHED();
            break;

        }
    }

    /*
     * At this point, buffer from b->pos to b->last has been parsed completely
     * but we haven't been able to reach to any conclusion. Normally, this
     * means that we have to parse again starting from the state we are in
     * after more data has been read. The newly read data is either read into
     * a new mbuf, if existing mbuf is full (b->last == b->end) or into the
     * existing mbuf.
     *
     * The only exception to this is when the existing mbuf is full (b->last
     * is at b->end) and token marker is set, which means that we have to
     * copy the partial token into a new mbuf and parse again with more data
     * read into new mbuf.
     */
    ASSERT(p == b->last);
    r->pos = p;
    r->state = state;

    if (b->last == b->end && r->token != NULL) {
        r->pos = r->token;
        r->token = NULL;
        r->result = MSG_PARSE_REPAIR;
    } else {
        r->result = MSG_PARSE_AGAIN;
    }

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed req %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;

done:
    ASSERT(r->type > MSG_UNKNOWN && r->type < MSG_SENTINEL);
    r->pos = p + 1;
    ASSERT(r->pos <= b->last);
    r->state = SW_START;
    r->result = MSG_PARSE_OK;

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed req %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;

enomem:
    r->result = MSG_PARSE_ERROR;
    r->state = state;

    log_hexdump(LOG_INFO, b->pos, mbuf_length(b), "out of memory on parse req %"PRIu64" "
                "res %d type %d state %d", r->id, r->result, r->type, r->state);

    return;

error:
    r->result = MSG_PARSE_ERROR;
    r->state = state;	
	errno = EINVAL;

    log_hexdump(LOG_INFO, b->pos, mbuf_length(b), "parsed bad req %"PRIu64" "
                "res %d type %d state %d", r->id, r->result, r->type,
                r->state);
}

static rstatus_t
manage_help_make_reply(struct context *ctx, struct msg *msg)
{
    rstatus_t status;
    struct conn *conn;
    char *contents;
    char *line = "**********************************\x0d\x0a";

    ASSERT(!msg->request);

    conn = msg->owner;
    ASSERT(conn->client && !conn->proxy);

    status = msg_append_full(msg, (uint8_t *)line, strlen(line));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }
    
	contents = " COMMAND  : help\x0d\x0a DESCRIBE : display this message\x0d\x0a USAGE    : no args\x0d\x0a";
	status = msg_append_full(msg, (uint8_t *)contents, strlen(contents));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }
	status = msg_append_full(msg, (uint8_t *)line, strlen(line));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }

    contents = " COMMAND  : status\x0d\x0a DESCRIBE : display the proxy status\x0d\x0a USAGE    : no args\x0d\x0a";
	status = msg_append_full(msg, (uint8_t *)contents, strlen(contents));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }
	status = msg_append_full(msg, (uint8_t *)line, strlen(line));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }

    contents = " COMMAND  : find_key\x0d\x0a DESCRIBE : display a server which the key is belong to\x0d\x0a USAGE    : find_key poolname key\x0d\x0a";
	status = msg_append_full(msg, (uint8_t *)contents, strlen(contents));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }
	status = msg_append_full(msg, (uint8_t *)line, strlen(line));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }

	contents = " COMMAND  : find_keys\x0d\x0a DESCRIBE : display servers which the keys are belong to\x0d\x0a USAGE    : find_key poolname key1 key2 ...\x0d\x0a";
	status = msg_append_full(msg, (uint8_t *)contents, strlen(contents));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }
	status = msg_append_full(msg, (uint8_t *)line, strlen(line));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }

    contents = " COMMAND  : slowlog\x0d\x0a DESCRIBE : display and control the slowlog\x0d\x0a USAGE    : slowlog <subcommand(get|len|reset)> [argument]\x0d\x0a";
	status = msg_append_full(msg, (uint8_t *)contents, strlen(contents));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }
	status = msg_append_full(msg, (uint8_t *)line, strlen(line));
	if (status != NC_OK) {
		conn->err = ENOMEM;
		return status;
    }

    return NC_OK;
}

static rstatus_t
manage_findkey_make_reply(struct context *ctx, 
	struct conn *conn, struct msg *msg, struct msg *pmsg)
{
	rstatus_t status;
	uint32_t nkeys;
	struct server_pool *sp;
	struct server *server;
	struct keypos *kp;
    uint32_t idx;
	char *contents;
	
	ASSERT(conn->client && !conn->proxy);
    ASSERT(msg->request);
	ASSERT(pmsg != NULL && !pmsg->request);
    ASSERT(msg->owner == conn);
	ASSERT(conn->owner == ctx->manager);

	nkeys = array_n(msg->keys);
	ASSERT(nkeys == 2);

	kp = array_get(msg->keys, 0);
	sp = server_pools_server_pool(&ctx->pool, kp->start, (uint32_t)(kp->end - kp->start));
	if (sp == NULL) {
        contents = "ERR: pool doesn't exist!\x0d\x0a";
        status = msg_append_full(pmsg, (uint8_t *)contents, strlen(contents));
        if (status != NC_OK) {
            conn->err = ENOMEM;
    		return status;
        }
		return NC_OK;
	}

	kp = array_get(msg->keys, 1);
    idx = server_pool_idx(sp, kp->start, (uint32_t)(kp->end - kp->start));
	server = array_get(&sp->server, idx);
    
	status = msg_append_full(pmsg, server->pname.data, server->pname.len);
    if (status != NC_OK) {
        conn->err = ENOMEM;
        return status;
    }

	status = msg_append_full(pmsg, (uint8_t *)" ", 1);
    if (status != NC_OK) {
        conn->err = ENOMEM;
		return status;
    }

	status = msg_append_full(pmsg, server->name.data, server->name.len);
    if (status != NC_OK) {
        conn->err = ENOMEM;
		return status;
    }

	status = msg_append_full(pmsg, (uint8_t *)CRLF, CRLF_LEN);
    if (status != NC_OK) {
		conn->err = ENOMEM;
        return status;
    }

	return NC_OK;
}

static rstatus_t
manage_findkeys_make_reply(struct context *ctx, 
	struct conn *conn, struct msg *msg, struct msg *pmsg)
{
	rstatus_t status;
	uint32_t nkeys;
	struct server_pool *sp;
	struct server *server;
	struct keypos *kp;
    uint32_t i, idx;
	char *contents;
	
	ASSERT(conn->client && !conn->proxy);
    ASSERT(msg->request);
	ASSERT(pmsg != NULL && !pmsg->request);
    ASSERT(msg->owner == conn);
	ASSERT(conn->owner == ctx->manager);

	nkeys = array_n(msg->keys);
	ASSERT(nkeys >= 2);

	kp = array_get(msg->keys, 0);
	sp = server_pools_server_pool(&ctx->pool, kp->start, (uint32_t)(kp->end - kp->start));
	if (sp == NULL) {
        contents = "ERR: pool doesn't exist!\x0d\x0a";
        status = msg_append_full(pmsg, (uint8_t *)contents, strlen(contents));
        if (status != NC_OK) {
            conn->err = ENOMEM;
    		return status;
        }
		return NC_OK;
	}

    for(i = 1; i < nkeys; i ++)
	{
    	kp = array_get(msg->keys, i);
        idx = server_pool_idx(sp, kp->start, (uint32_t)(kp->end - kp->start));
    	server = array_get(&sp->server, idx);
        
    	status = msg_append_full(pmsg, server->pname.data, server->pname.len);
        if (status != NC_OK) {
            conn->err = ENOMEM;
            return status;
        }

    	status = msg_append_full(pmsg, (uint8_t *)" ", 1);
        if (status != NC_OK) {
            conn->err = ENOMEM;
    		return status;
        }

    	status = msg_append_full(pmsg, server->name.data, server->name.len);
        if (status != NC_OK) {
            conn->err = ENOMEM;
    		return status;
        }

    	status = msg_append_full(pmsg, (uint8_t *)CRLF, CRLF_LEN);
        if (status != NC_OK) {
    		conn->err = ENOMEM;
            return status;
        }
    }
    
	return NC_OK;
}

rstatus_t
manage_reply(struct context *ctx, struct msg *r)
{
    struct conn *conn;
    struct msg *resp = r->peer;

    ASSERT(resp != NULL && resp->owner != NULL);
    ASSERT(ctx->role == NC_CONTEXT_ROLE_MASTER);

    conn = resp->owner;

    switch (r->type) {
    case MSG_REQ_PROXY_STATUS:
        stats_aggregate(ctx);
        stats_make_rsp(ctx->stats);
        return msg_append_full(resp, ctx->stats->buf.data, ctx->stats->buf.len);
        break;
    case MSG_REQ_PROXY_HELP:
        return manage_help_make_reply(ctx, resp);
        break;
    case MSG_REQ_PROXY_FIND_KEY:
        return manage_findkey_make_reply(ctx, conn, r, resp);
        break;
    case MSG_REQ_PROXY_FIND_KEYS:
        return manage_findkeys_make_reply(ctx, conn, r, resp);
        break;
    case MSG_REQ_PROXY_SLOWLOG:
        return slowlog_command_make_reply(ctx, conn, r, resp);
        break;
    default:
        return NC_ERROR;
        break;
    }

    return NC_OK;
}

bool
manage_failure(struct msg *r)
{
    return false;
}

rstatus_t
manage_add_auth(struct context *ctx, struct conn *c_conn, struct conn *s_conn)
{
    NOT_REACHED();
    return NC_OK;
}

rstatus_t
manage_fragment(struct msg *r, uint32_t ncontinuum, struct msg_tqh *frag_msgq)
{
    return NC_OK;
}

void
manage_pre_coalesce(struct msg *r)
{
    
}

void
manage_post_coalesce(struct msg *r)
{

}

static rstatus_t
manage_listen(struct context *ctx, struct conn *p)
{
    rstatus_t status;
    struct manage *manager = p->owner;

    ASSERT(p->proxy);

    p->sd = socket(p->family, SOCK_STREAM, 0);
    if (p->sd < 0) {
        log_error("socket failed: %s", strerror(errno));
        return NC_ERROR;
    }

    status = nc_set_reuseaddr(p->sd);
    if (status < 0) {
        log_error("set reuseaddr on m %d failed for management: %s", p->sd, strerror(errno));
        return NC_ERROR;
    }

    status = bind(p->sd, p->addr, p->addrlen);
    if (status < 0) {
        log_error("bind on p %d to addr '%.*s:%d' failed for management: %s", p->sd,
                  manager->addrstr.len, manager->addrstr.data, manager->port, strerror(errno));
        return NC_ERROR;
    }

    status = listen(p->sd, 128);
    if (status < 0) {
        log_error("listen on p %d on addr '%.*s' failed for management: %s", p->sd,
                  manager->addrstr.len, manager->addrstr.data, strerror(errno));
        return NC_ERROR;
    }

    status = nc_set_nonblocking(p->sd);
    if (status < 0) {
        log_error("set nonblock on p %d on addr '%.*s' failed for management: %s", p->sd,
                  manager->addrstr.len, manager->addrstr.data, strerror(errno));
        return NC_ERROR;
    }

    status = event_add_conn(ctx->evb, p);
    if (status < 0) {
        log_error("event add conn p %d on addr '%.*s' failed for management: %s",
                  p->sd, manager->addrstr.len, manager->addrstr.data,
                  strerror(errno));
        return NC_ERROR;
    }

    status = event_del_out(ctx->evb, p);
    if (status < 0) {
        log_error("event del out p %d on addr '%.*s' failed for management: %s",
                  p->sd, manager->addrstr.len, manager->addrstr.data,
                  strerror(errno));
        return NC_ERROR;
    }

    return NC_OK;
}


rstatus_t
manage_init(struct context *ctx, char *addr, uint16_t port)
{
    rstatus_t status;
    struct manage *manager;
    struct conn *p;

    ASSERT(ctx->manager == NULL);

    manager = nc_alloc(sizeof(struct manage));
    if (manager == NULL) {
        return NC_ENOMEM;
    }

    manager->nc_conn_q = 0;
    TAILQ_INIT(&manager->c_conn_q);
    string_init(&manager->addrstr);

    ctx->manager = manager;
    manager->ctx = ctx;

    string_copy(&manager->addrstr, (uint8_t *)addr, (uint32_t)strlen(addr));
    manager->port = port;

    memset(&manager->info, 0, sizeof(manager->info));
    status = nc_resolve(&manager->addrstr, manager->port, &manager->info);
    if (status != NC_OK) {
        return NC_ERROR;
    }

    p = conn_get_manage(manager);
    if (p == NULL) {
        return NC_ERROR;
    }

    status = manage_listen(ctx, p);
    if (status != NC_OK) {
        p->close(ctx, p);
        return status;
    }

    log_debug(LOG_NOTICE, "p %d listening on '%s:%u' for management", p->sd, addr, port);

    return NC_OK;
}

void
manage_deinit(struct context *ctx)
{
    struct manage *manager = ctx->manager;
    struct conn *p;

    if (manager == NULL) {
        return;
    }

    p = manager->p_conn;
    if (p != NULL) {
        p->close(ctx, p);
    }

    string_deinit(&manager->addrstr);

    nc_free(manager);
    ctx->manager = NULL;
}

void
manage_ref(struct conn *conn, void *owner)
{
    struct manage *manager = owner;
    ASSERT(!conn->client && conn->proxy);
    ASSERT(conn->owner == NULL);

    conn->family = manager->info.family;
    conn->addrlen = manager->info.addrlen;
    conn->addr = (struct sockaddr *)&manager->info.addr;

    manager->p_conn = conn;

    /* owner of the proxy connection is the manage */
    conn->owner = owner;

    log_debug(LOG_VVERB, "ref conn %p owner %p for manage", conn, manager);
}

void
manage_unref(struct conn *conn)
{
    struct manage *manager;

    ASSERT(!conn->client && conn->proxy);
    ASSERT(conn->owner != NULL);

    manager = conn->owner;
    conn->owner = NULL;

    manager->p_conn = NULL;

    log_debug(LOG_VVERB, "unref conn %p owner %p for manage", conn, manager);
}

