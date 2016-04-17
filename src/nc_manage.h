#ifndef _NC_MANAGE_H_
#define _NC_MANAGE_H_

#include <nc_core.h>

struct manage {
    struct context     *ctx;

    struct string      addrstr;              /* pool address - hostname:port (ref in conf_pool) */
    uint16_t           port;                 /* port */
    struct sockinfo    info;                 /* listen socket info */

    struct conn        *p_conn;
    uint32_t           nc_conn_q;            /* # client connection */
    struct conn_tqh    c_conn_q;             /* client connection q */
};

void manage_parse_req(struct msg *r);
rstatus_t manage_reply(struct context *ctx, struct msg *r);
bool manage_failure(struct msg *r);
rstatus_t manage_add_auth(struct context *ctx, struct conn *c_conn, struct conn *s_conn);
rstatus_t manage_fragment(struct msg *r, uint32_t ncontinuum, struct msg_tqh *frag_msgq);
void manage_pre_coalesce(struct msg *r);
void manage_post_coalesce(struct msg *r);
rstatus_t manage_init(struct context *ctx, char *addr, uint16_t port);
void manage_deinit(struct context *ctx);
void manage_ref(struct conn *conn, void *owner);
void manage_unref(struct conn *conn);



#endif
