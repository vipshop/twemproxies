#include <nc_core.h>

#define SLOWLOG_LOG_SLOWER_THAN     10000
#define SLOWLOG_MAX_LEN             256

#define SLOWLOG_STATISTICS_PERIOD   24
#define SLOWLOG_STATISTICS_DAYS     30

#define SLOWLOG_ENTRY_MAX_KEYS      32
#define SLOWLOG_ENTRY_MAX_STRING    128

STAILQ_HEAD(slowloghdr, slowlog_entry);

static pthread_rwlock_t rwlocker;
static struct slowloghdr slowlog;     /* SLOWLOG queue of commands */
static int  slowlog_len;               /* SLOWLOG queue length */
static long long slowlog_entry_id;    /* SLOWLOG current entry ID */

static long long slowlog_log_slower_than = -1;  /* Unit is microseconds */
static int slowlog_max_len = 10;

struct statistics_oneday {
    int year;
    int mon;
    int day;

    long long *periods;
};
static int statistics_period;  /* The statistics period count for one day to split  */
static int statistics_days;    /* Store the statistics of the last few days */
static struct statistics_oneday *slowlog_statistics; /* Array to store slowlog statistics */
static int today_idx;          /* The write idx in the slowlog_statistics array */
static pthread_mutex_t statistics_locker;

/* Create a new slowlog entry.
 * Incrementing the ref count of all the objects retained is up to
 * this function. */
static slowlog_entry *slowlog_create_entry(struct msg *r, long long duration) {
    slowlog_entry *se = nc_alloc(sizeof(*se));
    uint32_t j, keys_count, keys_count_input;

    se->cmdtype = r->type;

    keys_count_input = keys_count = r->keys==NULL?0:array_n(r->keys);

    if (keys_count_input > SLOWLOG_ENTRY_MAX_KEYS) keys_count_input = SLOWLOG_ENTRY_MAX_KEYS;
    se->keys_count = (int)keys_count;
    if (keys_count_input > 0) {
        se->keys = array_create(keys_count_input, sizeof(struct string));
        for (j = 0; j < keys_count_input; j ++) {
            struct keypos *kp = array_get(r->keys, j);
            struct string *key = array_push(se->keys);
            uint32_t key_len = (uint32_t)(kp->end-kp->start);
            string_init(key);
            if (key_len > SLOWLOG_ENTRY_MAX_STRING) {
                int len;
                uint8_t buf[SLOWLOG_ENTRY_MAX_STRING+50];
                memcpy(buf,kp->start,SLOWLOG_ENTRY_MAX_STRING);
                len = nc_scnprintf(buf+SLOWLOG_ENTRY_MAX_STRING,
                    50,"... (%lu more bytes)",
                    key_len-SLOWLOG_ENTRY_MAX_STRING);            
                if (len > 0) {
                    string_copy(key,buf,SLOWLOG_ENTRY_MAX_STRING+(uint32_t)len);
                } else {
                    string_copy(key,kp->start,SLOWLOG_ENTRY_MAX_STRING);
                }
            } else {
                string_copy(key,kp->start,key_len);
            }
        }
    }else {
        se->keys = NULL;
    }
    
    se->time = time(NULL);
    se->duration = duration;

    STAILQ_NEXT(se, next) = NULL;
    
    return se;
}

/* Free a slow log entry. The argument is void so that the prototype of this
 * function matches the one of the 'free' method of adlist.c.
 *
 * This function will take care to release all the retained object. */
static void slowlog_free_entry(slowlog_entry *se) {
    if (se->keys) {
        struct string *key;
        while (array_n(se->keys) > 0) {
            key = array_pop(se->keys);
            string_deinit(key);
        }
        
        array_destroy(se->keys);
    }
    
    nc_free(se);
}

static int slowlog_statistics_init(void)
{
    int i;

    slowlog_statistics = NULL;
    today_idx = 0;
    if (statistics_period == 0 || statistics_days == 0)
        return NC_OK;

    pthread_mutex_init(&statistics_locker,NULL);
    slowlog_statistics = nc_calloc(statistics_days,sizeof(struct statistics_oneday));
    if (slowlog_statistics == NULL)
        return NC_ENOMEM;

    for (i = 0; i < statistics_days; i ++) {
        slowlog_statistics[i].year = 0;
        slowlog_statistics[i].mon = 0;
        slowlog_statistics[i].day = 0;
        slowlog_statistics[i].periods = nc_calloc(statistics_period,sizeof(long long));
        if (slowlog_statistics[i].periods == NULL)
            return NC_ENOMEM;
    }

    return NC_OK;
}

static void slowlog_statistics_oneday_reset(struct statistics_oneday *so)
{
    int j;

    if (so == NULL || statistics_period == 0)
        return;

    pthread_mutex_lock(&statistics_locker);
    so->year = 0;
    so->mon = 0;
    so->day = 0;
    for (j = 0; j < statistics_period; j ++) {
        so->periods[j] = 0;
    }
    pthread_mutex_unlock(&statistics_locker);
}

static void slowlog_statistics_input(void)
{
    time_t timep;
    struct tm ptm = { 0 };  
    struct statistics_oneday *today;
    int idx;

    if (slowlog_statistics == NULL) {
        return;
    }
    
    time(&timep);
    localtime_r(&timep, &ptm);

    pthread_mutex_lock(&statistics_locker);
    ASSERT(today_idx < statistics_days);
    today = &slowlog_statistics[today_idx];
    ASSERT(today->year <= ptm.tm_year);

    if (today->year == 0) {
        today->year = ptm.tm_year;
        today->mon = ptm.tm_mon;
        today->day = ptm.tm_mday;
    } else if (today->year != ptm.tm_year || 
        today->mon != ptm.tm_mon || 
        today->day != ptm.tm_mday) {
        today_idx ++;
        if (today_idx >= statistics_days) {
            today_idx = 0;
        }
        today = &slowlog_statistics[today_idx];
        slowlog_statistics_oneday_reset(today);
        today->year = ptm.tm_year;
        today->mon = ptm.tm_mon;
        today->day = ptm.tm_mday;
    }

    ASSERT(ptm.tm_hour < 24);
    switch (statistics_period) {
    case 12:
        idx = ptm.tm_hour/2;
        break;
    case 24:
        idx = ptm.tm_hour;
        break;
    case 48:
        idx = ptm.tm_hour*2;
        if (ptm.tm_min >= 30)
            idx++;
        break;
    case 96:
        idx = ptm.tm_hour*4;
        if (ptm.tm_min >= 45)
            idx += 3;
        else if (ptm.tm_min >= 30)
            idx += 2;
        else if (ptm.tm_min >= 15)
            idx += 1;
        break;
    default:
        idx = -1;
        break;
    }

    if (idx >=0 && idx < statistics_period)
        today->periods[idx]++;
    
    pthread_mutex_unlock(&statistics_locker);
}

/* Initialize the slow log. This function should be called a single time
 * at server startup. */
void slowlog_init(void) {
    pthread_rwlock_init(&rwlocker,NULL);
    STAILQ_INIT(&slowlog);
    slowlog_len = 0;
    slowlog_entry_id = 0;
    slowlog_max_len = SLOWLOG_MAX_LEN;
    
    slowlog_statistics_init();
}

/* Push a new entry into the slow log.
 * This function will make sure to trim the slow log accordingly to the
 * configured max length. 
 * The unit of duration is microseconds */
void slowlog_push_entry_if_needed(struct msg *r, long long duration) {
    if (slowlog_log_slower_than < 0) return; /* Slowlog disabled */
    if (duration >= slowlog_log_slower_than) {
        slowlog_entry *se = slowlog_create_entry(r,duration);
        pthread_rwlock_wrlock(&rwlocker);
        se->id = slowlog_entry_id++;
        STAILQ_INSERT_HEAD(&slowlog, se, next);

        if (slowlog_len >= slowlog_max_len) {
            se = STAILQ_LAST(&slowlog, slowlog_entry, next);
            STAILQ_REMOVE(&slowlog, se, slowlog_entry, next);
            slowlog_free_entry(se);
        } else {
            slowlog_len ++;
        }
        pthread_rwlock_unlock(&rwlocker);

        slowlog_statistics_input();
    }
}

/* Remove all the entries from the current slow log. */
static void slowlog_reset(void) {
    pthread_rwlock_wrlock(&rwlocker);
    while (!STAILQ_EMPTY(&slowlog)) {
        slowlog_entry *se = STAILQ_FIRST(&slowlog);
        STAILQ_REMOVE_HEAD(&slowlog, next);
        slowlog_free_entry(se);
        slowlog_len--;
    }
    ASSERT(slowlog_len == 0);
    pthread_rwlock_unlock(&rwlocker);
}

rstatus_t
slowlog_command_make_reply(struct context *ctx, 
	struct conn *conn, struct msg *msg, struct msg *pmsg)
{
	rstatus_t status;
	uint32_t nkeys;
	struct keypos *kp;
	char *contents;
    uint32_t subcmdlen;
	
	ASSERT(conn->client && !conn->proxy);
    ASSERT(msg->request);
	ASSERT(pmsg != NULL && !pmsg->request);
    ASSERT(msg->owner == conn);
	ASSERT(conn->owner == ctx->manager);

	nkeys = array_n(msg->keys);
	ASSERT(nkeys >= 1);

	kp = array_get(msg->keys, 0);
    subcmdlen = (uint32_t)(kp->end-kp->start);
    if (subcmdlen==strlen("reset")&&!memcmp(kp->start,"reset",subcmdlen)){
        if (nkeys != 1) {
            goto format_error;
        }
        
        slowlog_reset();
        status = msg_append_full(pmsg, (uint8_t*)"OK", 2);
        if (status != NC_OK) {
    		conn->err = ENOMEM;
            return status;
        }
        
        goto done;
    } else if (subcmdlen==strlen("id")&&!memcmp(kp->start,"id",subcmdlen)){
        int buf_len;
        uint8_t buf[30];
        long long id;

        if (nkeys != 1) {
            goto format_error;
        }

        pthread_rwlock_rdlock(&rwlocker);
        id = slowlog_entry_id;
        pthread_rwlock_unlock(&rwlocker);
        
        buf_len = nc_scnprintf(buf,30,"%lld",id);
        status = msg_append_full(pmsg, buf, (size_t)buf_len);
        if (status != NC_OK) {
    		conn->err = ENOMEM;
            return status;
        }
        goto done;
    } else if (subcmdlen==strlen("len")&&!memcmp(kp->start,"len",subcmdlen)){
        int len, buf_len;
        uint8_t buf[20];

        if (nkeys != 1) {
            goto format_error;
        }

        pthread_rwlock_rdlock(&rwlocker);
        len = slowlog_len;
        pthread_rwlock_unlock(&rwlocker);
        
        buf_len = nc_scnprintf(buf,20,"%d",len);
        status = msg_append_full(pmsg, buf, (size_t)buf_len);
        if (status != NC_OK) {
    		conn->err = ENOMEM;
            return status;
        }
        goto done;
    } else if (subcmdlen==strlen("get")&&!memcmp(kp->start,"get",subcmdlen)){
        int count, sent = 0, buf_len;
        uint8_t buf[50];
        slowlog_entry *se;
        struct string *str;
        
        if (nkeys == 1) {
            count = 10;
        } else if (nkeys == 2) {
            kp = array_get(msg->keys, 1);
            count = nc_atoi(kp->start, (kp->end-kp->start));
            if (count < 0) {
                goto format_error;
            }
        } else {
            goto format_error;
        }

        pthread_rwlock_rdlock(&rwlocker);
        se = STAILQ_FIRST(&slowlog);
        while(count-- && se != NULL) {
            int nfield;
            uint32_t j;            

            sent++;
            buf_len = nc_scnprintf(buf,50,"%d) 1) %lld\r\n",sent, se->id);
            status = msg_append_full(pmsg, buf, (size_t)buf_len);
            if (status != NC_OK) {
                pthread_rwlock_unlock(&rwlocker);
        		conn->err = ENOMEM;
                return status;
            }
            buf_len = nc_scnprintf(buf,50,"    2) %lld\r\n",se->time);
            status = msg_append_full(pmsg, buf, (size_t)buf_len);
            if (status != NC_OK) {
                pthread_rwlock_unlock(&rwlocker);
        		conn->err = ENOMEM;
                return status;
            }
            buf_len = nc_scnprintf(buf,50,"    3) %lld\r\n",se->duration);
            status = msg_append_full(pmsg, buf, (size_t)buf_len);
            if (status != NC_OK) {
                pthread_rwlock_unlock(&rwlocker);
        		conn->err = ENOMEM;
                return status;
            }
            str = msg_type_string(se->cmdtype);
            nfield = 1;
            buf_len = nc_scnprintf(buf,50,"    4) %d) %s\r\n",nfield++,str->data);
            status = msg_append_full(pmsg, buf, (size_t)buf_len);
            if (status != NC_OK) {
                pthread_rwlock_unlock(&rwlocker);
        		conn->err = ENOMEM;
                return status;
            }
            buf_len = nc_scnprintf(buf,50,"       %d) %d\r\n",nfield++,se->keys_count);
            status = msg_append_full(pmsg, buf, (size_t)buf_len);
            if (status != NC_OK) {
                pthread_rwlock_unlock(&rwlocker);
        		conn->err = ENOMEM;
                return status;
            }
            if (se->keys != NULL) {
                for (j = 0; j < array_n(se->keys); j ++) {
                    str = array_get(se->keys, j);
                    
                    buf_len = nc_scnprintf(buf,50,"       %d) ",nfield++);
                    status = msg_append_full(pmsg, buf, (size_t)buf_len);
                    if (status != NC_OK) {
                        pthread_rwlock_unlock(&rwlocker);
                		conn->err = ENOMEM;
                        return status;
                    }
                    status = msg_append_full(pmsg, str->data, (size_t)str->len);
                    if (status != NC_OK) {
                        pthread_rwlock_unlock(&rwlocker);
                		conn->err = ENOMEM;
                        return status;
                    }
                    status = msg_append_full(pmsg, (uint8_t *)CRLF, CRLF_LEN);
                    if (status != NC_OK) {
                        pthread_rwlock_unlock(&rwlocker);
                		conn->err = ENOMEM;
                        return status;
                    }
                }
            }
            se = STAILQ_NEXT(se, next);
        }
        pthread_rwlock_unlock(&rwlocker);
        
        if (msg_empty(pmsg)) {
            status = msg_append_full(pmsg, (uint8_t*)"END", 3);
            if (status != NC_OK) {
        		conn->err = ENOMEM;
                return status;
            }
            goto done;
        }
        return NC_OK;
    } else if (subcmdlen==strlen("overview") &&
        !memcmp(kp->start,"overview",subcmdlen)){
        int count, buf_len;
        uint8_t buf[50];
        int j, idx, id;
        struct statistics_oneday *so;
        
        if (nkeys == 1) {
            count = 10;
        } else if (nkeys == 2) {
            kp = array_get(msg->keys, 1);
            count = nc_atoi(kp->start, (kp->end-kp->start));
            if (count < 0) {
                goto format_error;
            }
        } else {
            goto format_error;
        }

        if (slowlog_statistics == NULL) {
            status = msg_append_full(pmsg, (uint8_t*)"END", 3);
            if (status != NC_OK) {
        		conn->err = ENOMEM;
                return status;
            }
            goto done;
        }

        if (count > statistics_days)
            count = statistics_days;
        pthread_mutex_lock(&statistics_locker);
        idx = today_idx;
        id = 1;
        while (count--) {
            so = &slowlog_statistics[idx];

            if (so->year == 0)
                break;

            buf_len = nc_scnprintf(buf,50,"%d) %d-%d-%d ",id++,so->year+1900,so->mon+1,so->day);
            status = msg_append_full(pmsg, buf, (size_t)buf_len);
            if (status != NC_OK) {
                pthread_mutex_unlock(&statistics_locker);
        		conn->err = ENOMEM;
                return status;
            }

            for (j = 0; j < statistics_period-1; j ++) {
                buf_len = nc_scnprintf(buf,50,"%lld ",so->periods[j]);
                status = msg_append_full(pmsg, buf, (size_t)buf_len);
                if (status != NC_OK) {
                    pthread_mutex_unlock(&statistics_locker);
            		conn->err = ENOMEM;
                    return status;
                }
            }
            buf_len = nc_scnprintf(buf,50,"%lld\r\n",so->periods[statistics_period-1]);
            status = msg_append_full(pmsg, buf, (size_t)buf_len);
            if (status != NC_OK) {
                pthread_mutex_unlock(&statistics_locker);
        		conn->err = ENOMEM;
                return status;
            }
            
            if (--idx < 0) {
                idx = statistics_days - 1;
                if (slowlog_statistics[idx].year == 0) {
                    break;
                }
            }
        }
        pthread_mutex_unlock(&statistics_locker);

        if (msg_empty(pmsg)) {
            status = msg_append_full(pmsg, (uint8_t*)"END", 3);
            if (status != NC_OK) {
        		conn->err = ENOMEM;
                return status;
            }
            goto done;
        }
        return NC_OK;
    } else {
        goto format_error;
    }

format_error:
    contents = "ERR: slowlog command format is error.";
    status = msg_append_full(pmsg, (uint8_t *)contents, strlen(contents));
    if (status != NC_OK) {
		conn->err = ENOMEM;
        return status;
    }
    
    goto done;
done:
    status = msg_append_full(pmsg, (uint8_t *)CRLF, CRLF_LEN);
    if (status != NC_OK) {
		conn->err = ENOMEM;
        return status;
    }
	return NC_OK;
}

int slowlog_parse_option(char *options)
{
    char *pos, *begin, *end;
    int value;

    if (options == NULL)
        return NC_ERROR;

    begin = options;
    end = options + strlen(options);

    pos = strstr(begin, ",");
    if (pos == NULL)
        return NC_ERROR;
    if (pos == begin) {
        slowlog_log_slower_than = SLOWLOG_LOG_SLOWER_THAN;
    } else {
        value = nc_atoi(begin,pos-begin);
        if (value < 0)
            return NC_ERROR;
        slowlog_log_slower_than = (long long)value;
    }

    begin = pos+1;
    if (begin > end)
        return NC_ERROR;
    pos = strstr(begin, ",");
    if (pos == NULL)
        return NC_ERROR;
    if (pos == begin) {
        statistics_period = SLOWLOG_STATISTICS_PERIOD;
    } else {
        value = nc_atoi(begin,pos-begin);
        if (value < 0)
            return NC_ERROR;
        if (value != 12 && value != 24 && 
            value != 48 && value != 96) {
            return NC_ERROR;
        }
        statistics_period = value;
    }

    begin = pos+1;
    if (begin > end) {
        statistics_days = SLOWLOG_STATISTICS_DAYS;
        return NC_OK;
    }
    value = nc_atoi(begin,end-begin);
    if (value < 0)
        return NC_ERROR;
    statistics_days = value;

    return NC_OK;    
}
