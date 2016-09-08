#ifndef _NC_SLOWLOG_H_
#define _NC_SLOWLOG_H_

#define SLOWLOG_LOG_SLOWER_THAN  10000
#define SLOWLOG_MAX_LEN          128

/* This structure defines an entry inside the slow log list */
typedef struct slowlog_entry {
    int cmdtype;
    int keys_count;
    struct array *keys;  /* Type is string */
    
    long long id;       /* Unique entry identifier. */
    long long duration; /* Time spent by the query, in nanoseconds. */
    time_t time;        /* Unix time at which the query was executed. */

    STAILQ_ENTRY(slowlog_entry) next;    /* next slowlog_entry */
} slowlog_entry;

/* Exported API */
void slowlog_init(long long slower_than, int max_length);
void slowlog_push_entry_if_needed(struct msg *r, long long duration);

/* Exported commands */
rstatus_t slowlog_command_make_reply(struct context *ctx, struct conn *conn, struct msg *msg, struct msg *pmsg);

#endif
