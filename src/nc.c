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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include <nc_core.h>
#include <nc_conf.h>
#include <nc_signal.h>

#define NC_CONF_PATH        "conf/nutcrackers.yml"

#define NC_LOG_DEFAULT      LOG_NOTICE
#define NC_LOG_MIN          LOG_EMERG
#define NC_LOG_MAX          LOG_PVERB
#define NC_LOG_PATH         NULL

#define NC_PORT             22222
#define NC_ADDR             "0.0.0.0"
#define NC_INTERVAL         (30 * 1000) /* in msec */

#define NC_PID_FILE         NULL

#define NC_MBUF_SIZE        MBUF_SIZE
#define NC_MBUF_MIN_SIZE    MBUF_MIN_SIZE
#define NC_MBUF_MAX_SIZE    MBUF_MAX_SIZE

#define NC_THREAD_NUM_DEFAULT	(sysconf(_SC_NPROCESSORS_ONLN)>6?6:sysconf(_SC_NPROCESSORS_ONLN))

static int show_help;
static int show_version;
static int test_conf;
static int daemonize;
static int describe_stats;

static struct option long_options[] = {
    { "help",           no_argument,        NULL,   'h' },
    { "version",        no_argument,        NULL,   'V' },
    { "test-conf",      no_argument,        NULL,   't' },
    { "daemonize",      no_argument,        NULL,   'd' },
    { "describe-stats", no_argument,        NULL,   'D' },
    { "verbose",        required_argument,  NULL,   'v' },
    { "output",         required_argument,  NULL,   'o' },
    { "conf-file",      required_argument,  NULL,   'c' },
    { "port",           required_argument,  NULL,   's' },
    { "interval",       required_argument,  NULL,   'i' },
    { "addr",           required_argument,  NULL,   'a' },
    { "pid-file",       required_argument,  NULL,   'p' },
    { "mbuf-size",      required_argument,  NULL,   'm' },
    { "thread-num",     required_argument,  NULL,   'T' },
    { NULL,             0,                  NULL,    0  }
};

static char short_options[] = "hVtdDv:o:c:s:i:a:p:m:T:";

static rstatus_t
nc_daemonize(int dump_core)
{
    rstatus_t status;
    pid_t pid, sid;
    int fd;

    pid = fork();
    switch (pid) {
    case -1:
        log_error("fork() failed: %s", strerror(errno));
        return NC_ERROR;

    case 0:
        break;

    default:
        /* parent terminates */
        _exit(0);
    }

    /* 1st child continues and becomes the session leader */

    sid = setsid();
    if (sid < 0) {
        log_error("setsid() failed: %s", strerror(errno));
        return NC_ERROR;
    }

    if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
        log_error("signal(SIGHUP, SIG_IGN) failed: %s", strerror(errno));
        return NC_ERROR;
    }

    pid = fork();
    switch (pid) {
    case -1:
        log_error("fork() failed: %s", strerror(errno));
        return NC_ERROR;

    case 0:
        break;

    default:
        /* 1st child terminates */
        _exit(0);
    }

    /* 2nd child continues */

    /* change working directory */
    if (dump_core == 0) {
        status = chdir("/");
        if (status < 0) {
            log_error("chdir(\"/\") failed: %s", strerror(errno));
            return NC_ERROR;
        }
    }

    /* clear file mode creation mask */
    umask(0);

    /* redirect stdin, stdout and stderr to "/dev/null" */

    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        log_error("open(\"/dev/null\") failed: %s", strerror(errno));
        return NC_ERROR;
    }

    status = dup2(fd, STDIN_FILENO);
    if (status < 0) {
        log_error("dup2(%d, STDIN) failed: %s", fd, strerror(errno));
        close(fd);
        return NC_ERROR;
    }

    status = dup2(fd, STDOUT_FILENO);
    if (status < 0) {
        log_error("dup2(%d, STDOUT) failed: %s", fd, strerror(errno));
        close(fd);
        return NC_ERROR;
    }

    status = dup2(fd, STDERR_FILENO);
    if (status < 0) {
        log_error("dup2(%d, STDERR) failed: %s", fd, strerror(errno));
        close(fd);
        return NC_ERROR;
    }

    if (fd > STDERR_FILENO) {
        status = close(fd);
        if (status < 0) {
            log_error("close(%d) failed: %s", fd, strerror(errno));
            return NC_ERROR;
        }
    }

    return NC_OK;
}

static void
nc_print_run(struct instance *nci)
{
    int status;
    struct utsname name;

    status = uname(&name);
    if (status < 0) {
        loga("nutcrackers-%s started on pid %d", NC_VERSION_STRING, nci->pid);
    } else {
        loga("nutcracker-%s built for %s %s %s started on pid %d",
             NC_VERSION_STRING, name.sysname, name.release, name.machine,
             nci->pid);
    }

    loga("run, rabbit run / dig that hole, forget the sun / "
         "and when at last the work is done / don't sit down / "
         "it's time to dig another one");
}

static void
nc_print_done(void)
{
    loga("done, rabbit done");
}

static void
nc_show_usage(void)
{
    log_stderr(
        "Usage: nutcrackers [-?hVdDt] [-v verbosity level] [-o output file]" CRLF
        "                   [-c conf file] [-s manage port] [-a manage addr]" CRLF
        "                   [-i interval] [-p pid file] [-m mbuf size]" CRLF
        "                   [-T worker threads number]" CRLF
        "");
    log_stderr(
        "Options:" CRLF
        "  -h, --help             : this help" CRLF
        "  -V, --version          : show version and exit" CRLF
        "  -t, --test-conf        : test configuration for syntax errors and exit" CRLF
        "  -d, --daemonize        : run as a daemon" CRLF
        "  -D, --describe-stats   : print stats description and exit");
    log_stderr(
        "  -v, --verbose=N        : set logging level (default: %d, min: %d, max: %d)" CRLF
        "  -o, --output=S         : set logging file (default: %s)" CRLF
        "  -c, --conf-file=S      : set configuration file (default: %s)" CRLF
        "  -s, --port=N           : set manage port (default: %d)" CRLF
        "  -a, --addr=S           : set manage ip (default: %s)" CRLF
        "  -i, --interval=N       : set interval in msec (default: %d msec)" CRLF
        "  -p, --pid-file=S       : set pid file (default: %s)" CRLF
        "  -m, --mbuf-size=N      : set size of mbuf chunk in bytes (default: %d bytes)" CRLF
        "  -T, --thread_num=N     : set the worker threads number (default: %d)" CRLF
        "",
        NC_LOG_DEFAULT, NC_LOG_MIN, NC_LOG_MAX,
        NC_LOG_PATH != NULL ? NC_LOG_PATH : "stderr",
        NC_CONF_PATH,
        NC_PORT, NC_ADDR, NC_INTERVAL,
        NC_PID_FILE != NULL ? NC_PID_FILE : "off",
        NC_MBUF_SIZE,
        NC_THREAD_NUM_DEFAULT);
}

static rstatus_t
nc_create_pidfile(struct instance *nci)
{
    char pid[NC_UINTMAX_MAXLEN];
    int fd, pid_len;
    ssize_t n;

    fd = open(nci->pid_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        log_error("opening pid file '%s' failed: %s", nci->pid_filename,
                  strerror(errno));
        return NC_ERROR;
    }
    nci->pidfile = 1;

    pid_len = nc_snprintf(pid, NC_UINTMAX_MAXLEN, "%d", nci->pid);

    n = nc_write(fd, pid, pid_len);
    if (n < 0) {
        log_error("write to pid file '%s' failed: %s", nci->pid_filename,
                  strerror(errno));
        return NC_ERROR;
    }

    close(fd);

    return NC_OK;
}

static void
nc_remove_pidfile(struct instance *nci)
{
    int status;

    status = unlink(nci->pid_filename);
    if (status < 0) {
        log_error("unlink of pid file '%s' failed, ignored: %s",
                  nci->pid_filename, strerror(errno));
    }
}

static void
nc_set_default_options(struct instance *nci)
{
    int status;

    nci->ctx = NULL;

    nci->log_level = NC_LOG_DEFAULT;
    nci->log_filename = NC_LOG_PATH;

    nci->conf_filename = NC_CONF_PATH;

    nci->port = NC_PORT;
    nci->addr = NC_ADDR;
    nci->interval = NC_INTERVAL;

    status = nc_gethostname(nci->hostname, NC_MAXHOSTNAMELEN);
    if (status < 0) {
        log_warn("gethostname failed, ignored: %s", strerror(errno));
        nc_snprintf(nci->hostname, NC_MAXHOSTNAMELEN, "unknown");
    }
    nci->hostname[NC_MAXHOSTNAMELEN - 1] = '\0';

    nci->mbuf_chunk_size = NC_MBUF_SIZE;

    nci->pid = (pid_t)-1;
    nci->pid_filename = NULL;
    nci->pidfile = 0;

    nci->thread_num = (int)NC_THREAD_NUM_DEFAULT;
}

static rstatus_t
nc_get_options(int argc, char **argv, struct instance *nci)
{
    int c, value;

    opterr = 0;

    for (;;) {
        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            /* no more options */
            break;
        }

        switch (c) {
        case 'h':
            show_version = 1;
            show_help = 1;
            break;

        case 'V':
            show_version = 1;
            break;

        case 't':
            test_conf = 1;
            break;

        case 'd':
            daemonize = 1;
            break;

        case 'D':
            describe_stats = 1;
            show_version = 1;
            break;

        case 'v':
            value = nc_atoi(optarg, strlen(optarg));
            if (value < 0) {
                log_stderr("nutcrackers: option -v requires a number");
                return NC_ERROR;
            }
            nci->log_level = value;
            break;

        case 'o':
            nci->log_filename = optarg;
            break;

        case 'c':
            nci->conf_filename = optarg;
            break;

        case 's':
            value = nc_atoi(optarg, strlen(optarg));
            if (value < 0) {
                log_stderr("nutcrackers: option -s requires a number");
                return NC_ERROR;
            }
            if (!nc_valid_port(value)) {
                log_stderr("nutcrackers: option -s value %d is not a valid "
                           "port", value);
                return NC_ERROR;
            }

            nci->port = (uint16_t)value;
            break;

        case 'i':
            value = nc_atoi(optarg, strlen(optarg));
            if (value < 0) {
                log_stderr("nutcrackers: option -i requires a number");
                return NC_ERROR;
            }

            nci->interval = value;
            break;

        case 'a':
            nci->addr = optarg;
            break;

        case 'p':
            nci->pid_filename = optarg;
            break;

        case 'm':
            value = nc_atoi(optarg, strlen(optarg));
            if (value <= 0) {
                log_stderr("nutcrackers: option -m requires a non-zero number");
                return NC_ERROR;
            }

            if (value < NC_MBUF_MIN_SIZE || value > NC_MBUF_MAX_SIZE) {
                log_stderr("nutcrackers: mbuf chunk size must be between %zu and"
                           " %zu bytes", NC_MBUF_MIN_SIZE, NC_MBUF_MAX_SIZE);
                return NC_ERROR;
            }

            nci->mbuf_chunk_size = (size_t)value;
            break;
            
        case 'T':
            value = nc_atoi(optarg, strlen(optarg));
            if (value < 0) {
                log_stderr("nutcrackers: option -T requires a number");
                return NC_ERROR;
            }

            nci->thread_num = value;
            break;

        case '?':
            switch (optopt) {
            case 'o':
            case 'c':
            case 'p':
                log_stderr("nutcrackers: option -%c requires a file name",
                           optopt);
                break;

            case 'm':
            case 'v':
            case 's':
            case 'i':
            case 'T':
                log_stderr("nutcrackers: option -%c requires a number", optopt);
                break;

            case 'a':
                log_stderr("nutcrackers: option -%c requires a string", optopt);
                break;

            default:
                log_stderr("nutcrackers: invalid option -- '%c'", optopt);
                break;
            }
            return NC_ERROR;

        default:
            log_stderr("nutcrackers: invalid option -- '%c'", optopt);
            return NC_ERROR;

        }
    }

    return NC_OK;
}

/*
 * Returns true if configuration file has a valid syntax, otherwise
 * returns false
 */
static bool
nc_test_conf(struct instance *nci, bool test)
{
    struct conf *cf;

    cf = conf_create(nci->conf_filename);
    if (cf == NULL) {
        if (test)
            log_stderr("nutcrackers: configuration file '%s' syntax is invalid",
                nci->conf_filename);
        return false;
    }

    conf_destroy(cf);

    if (test)
        log_stderr("nutcrackers: configuration file '%s' syntax is ok",
            nci->conf_filename);
    return true;
}

static rstatus_t
nc_pre_run(struct instance *nci)
{
    rstatus_t status;

    status = log_init(nci->log_level, nci->log_filename);
    if (status != NC_OK) {
        return status;
    }

    if (!nc_test_conf(nci, false)) {
        log_error("conf file %s is error", nci->conf_filename);
        return NC_ERROR;
    }

    if (daemonize) {
        status = nc_daemonize(1);
        if (status != NC_OK) {
            return status;
        }
    }

    nci->pid = getpid();

    status = signal_init();
    if (status != NC_OK) {
        return status;
    }

    if (nci->pid_filename) {
        status = nc_create_pidfile(nci);
        if (status != NC_OK) {
            return status;
        }
    }

    STATS_LOCK_INIT();

    nc_print_run(nci);

    return NC_OK;
}

static void
nc_post_run(struct instance *nci)
{
    STATS_LOCK_DESTROY();

    if (nci->pidfile) {
        nc_remove_pidfile(nci);
    }

    signal_deinit();

    nc_print_done();

    log_deinit();
}

static void
nc_run(struct instance *nci)
{
    rstatus_t status;
    uint32_t i;
    uint32_t worker_count;
    struct array workers;
    struct thread_data *worker;

    if (nci->thread_num <= 0) {
        log_error("number of work threads must be greater than 0");
        return;
    } else if (nci->thread_num > 64) {
        log_warn("WARNING: Setting a high number of worker threads is not recommended."
            " Set this value to the number of cores in your machine or less.");
    }

    worker_count = (uint32_t)nci->thread_num;
    
    status = array_init(&workers, worker_count, sizeof(struct thread_data));
    if (status != NC_OK) {
        return;
    }
    
    /* init the workers */
    for (i = 0; i < worker_count; i ++) {
        worker = array_push(&workers);
        thread_data_init(worker);
        worker->nci = nci;

        status = setup_worker(worker);
        if (status != NC_OK) {
            exit(1);
        }
    }

    /* run the worker job */
    for (i = 0; i < worker_count; i ++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        worker = array_get(&workers, i);
        pthread_create(&worker->thread_id, 
        	&attr, worker_thread_run, worker);
    }

    status = master_run(nci, &workers);
    if (status != NC_OK) {
        exit(1);
    }

    /* wait for the worker finish */
	for(i = 0; i < worker_count; i ++){
		worker = array_get(&workers, i);
		pthread_join(worker->thread_id, NULL);
	}

    /* deinit the workers */
	for(i = 0; i < worker_count; i ++){
		worker = array_pop(&workers);
		thread_data_deinit(worker);
	}
}

int
main(int argc, char **argv)
{
    rstatus_t status;
    struct instance nci;

    nc_set_default_options(&nci);

    status = nc_get_options(argc, argv, &nci);
    if (status != NC_OK) {
        nc_show_usage();
        exit(1);
    }

    if (show_version) {
        log_stderr("This is nutcrackers-%s" CRLF, NC_VERSION_STRING);
        if (show_help) {
            nc_show_usage();
        }

        if (describe_stats) {
            stats_describe();
        }

        exit(0);
    }

    if (test_conf) {
        if (!nc_test_conf(&nci, true)) {
            exit(1);
        }
        exit(0);
    }

    status = nc_pre_run(&nci);
    if (status != NC_OK) {
        nc_post_run(&nci);
        exit(1);
    }

    nc_run(&nci);

    nc_post_run(&nci);

    exit(1);
}
