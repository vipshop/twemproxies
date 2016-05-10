/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _NC_THREAD_H_
#define _NC_THREAD_H_

STAILQ_HEAD(sulist, swapunit);

struct thread_data {
    int id;
    pthread_t thread_id;
    
    struct instance *nci;
    struct context *ctx;

    int socketpairs[2]; /*0: belong to master, 1: belong to worker*/
    struct conn *notice;
    
    struct sulist sul;
    pthread_mutex_t sullock;

    struct thread_stats *tstats;
};

struct swapunit {
    int sd;
    uint32_t pool_id;
    struct swapunit *next;
    STAILQ_ENTRY(swapunit) nextsu;    /* next swapunit */
};

struct swapunit *sui_new(void);
void sui_free(struct swapunit *item);

int thread_data_init(struct thread_data *tdata);
void thread_data_deinit(struct thread_data *tdata);

struct swapunit *sul_pop(struct thread_data *tdata);
void sul_push(struct thread_data *tdata, struct swapunit *su);

void dispatch_conn_new(int sd, uint32_t pool_id, struct array *workers);

rstatus_t notice_recv(struct context *ctx, struct conn *conn);
void notice_ref(struct conn *conn, void *owner);
void notice_unref(struct conn *conn);

int setup_worker(struct thread_data *worker);

int master_run(struct instance *nci, struct array *workers);
void *worker_thread_run(void *args);

#endif
