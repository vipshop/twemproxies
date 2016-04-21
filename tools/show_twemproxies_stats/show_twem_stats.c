#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "cJSON.h"
#include "util.h"

#define GET_ARRAY_LEN(array,len){len = (sizeof(array) / sizeof(array[0]));}

#define stats_size 20

static int idx = 0;

//0:memary 
//1:client_connections
//2:client_connections
//3:client_connections
//4:server_ejects_num
//5:server_connections
//6:requests_num
//7:request_bytes_num
//8:responses_num
//9:response_bytes_num
//10:in_queue_num
//11:out_queue_num
static long long stats_pre[stats_size];
static long long stats_now[stats_size];
static long long stats[stats_size];
static uint8_t stats_len;

static char str_line[1024];

static const char *mem_used_header = "VmRSS:";

static const char *proc_net_tcp="/proc/net/tcp";
static const char *delimiter_tcp=" ";
static const int address_column=1;
static const int st_column=3;
static const int inode_column=9;

static time_t timer;
static struct tm *tblock;

static const int content_name_interval = 26;

#define BYTES_RECEIVE_PRE_TIME 512
static char   buffer[BYTES_RECEIVE_PRE_TIME];
static char   *content = NULL;
static size_t content_size = 0;
static size_t content_len = 0;

int get_twem_used_memory(char * proc)
{
    int i = 0;
    long long mem_used = 0;
    char proc_file_path[25];
    FILE * proc_fd;
    char pid_num[10] = {0};
    
    if (proc == NULL) {
        return 0;
    }
    
    if (proc[0] == '/') {
        proc_fd = fopen(proc, "r");
        
        if (proc_fd == NULL) {
            printf("open pid file %s failed:%s \n", proc, strerror(errno));
            idx ++;
            goto error;
        }
        if (feof(proc_fd)) {
            printf("pid file %s is null:%s \n", proc, strerror(errno));
            idx ++;
            goto error;
        }
        fgets(str_line, 1024, proc_fd);
        if (strlen(str_line) >= 10) {
            printf("pid number in the pid file %s is to long!\n", proc);
            idx ++;
            goto error;
        }
        memcpy(pid_num, str_line, strlen(str_line));
        if (proc_fd != NULL) {
            fclose(proc_fd);
            proc_fd = NULL;
        }
    } else {
        if (strlen(proc) >= 10) {
            printf("pid number %s gived is to long!\n", proc);
            idx ++;
            return -1;
        }
        
        memcpy(pid_num, proc, strlen(proc));
    }
    
    int proc_id_len = strlen(pid_num);

    memset(proc_file_path, '\0', 25);
    proc_file_path[0] = '/';
    proc_file_path[1] = 'p';
    proc_file_path[2] = 'r';
    proc_file_path[3] = 'o';
    proc_file_path[4] = 'c';
    proc_file_path[5] = '/';
    for(i = 0; i < proc_id_len; i ++)
    {
        proc_file_path[6+i] = pid_num[i];
    }
    i += 6;
    proc_file_path[i++] = '/';
    proc_file_path[i++] = 's';
    proc_file_path[i++] = 't';
    proc_file_path[i++] = 'a';
    proc_file_path[i++] = 't';
    proc_file_path[i++] = 'u';
    proc_file_path[i++] = 's';
    
    proc_fd = fopen(proc_file_path, "r");

    if (proc_fd == NULL) {
        printf("open %s failed: %s\n", proc_file_path, strerror(errno));
        idx ++;
        goto error;
    }

    while (!feof(proc_fd)) { 
        {
            fgets(str_line, 1024, proc_fd);
            i ++;
            if (0 == strncmp(str_line, mem_used_header, strlen(mem_used_header))) {
                break;
            }
        }
    } 

    for (i = strlen(mem_used_header); i < strlen(str_line); i++) {
        if (isdigit(str_line[i])) {
            mem_used = mem_used * 10 + (uint32_t)(str_line[i] - '0');
        }
    }

    stats_now[idx] = mem_used;
    stats[idx] = stats_now[idx] - stats_pre[idx];
    idx ++;
    if (proc_fd != NULL) {
        fclose(proc_fd);
        proc_fd = NULL;
    }

    return 0;

error:

    if (proc_fd != NULL) {
        fclose(proc_fd);
        proc_fd = NULL;
    }

    return -1;
}

int get_proc_id_by_listened_port(int port)
{   
    char port_hex_string[10];
    dec2hex(port, port_hex_string);
    
    FILE * proc_net_tcp_fd;
    proc_net_tcp_fd = fopen(proc_net_tcp, "r");
    
    if (proc_net_tcp_fd == NULL) {
        printf("open %s failed!\n", proc_net_tcp);
        return -1;
    }   
    
    while (!feof(proc_net_tcp_fd)) {
        fgets(str_line, 1024, proc_net_tcp_fd);
        
        char *result = NULL;
        int i = 0;
        char address[30] = {0};
        char st[5] = {0};
        char inode[20] = {0};
        result = strtok(str_line, delimiter_tcp);
        while (result != NULL) {
            if (i == address_column) {
                stpcpy(address, result);
            } else if(i == st_column) {
                stpcpy(st, result);
            } else if (i == inode_column) {
                stpcpy(inode, result);
                break;
            }   
            
            result = strtok( NULL, delimiter_tcp);
            i ++;
        }
        if (address[0] == '\0' || st[0] == '\0' || inode[0] == '\0') {
            printf("parse %s error!\n", proc_net_tcp);
            return -1;
        }
        
        result = NULL;
        result = strtok(str_line, ":");
        if (result == NULL) {
            printf("parse tcp address in proc_net_tcp error!\n");
            return -1;
        }
        result = strtok(str_line, ":");
        if (result == NULL) {
            printf("parse tcp address in proc_net_tcp error!\n");
            return -1;
        }
        if (strcmp(result, address) == 0 && strcmp(st, "0A") == 0) {
            
            break;
        }
    }
    
    return 0;
}

static int get_stat_int(cJSON *root, char *stat_name)
{
    if (root == NULL) {
        return -1;
    }
    
    cJSON *stat = cJSON_GetObjectItem(root, stat_name);
    
    if (stat == NULL) {
        return -1;
    }
    
    return stat->valueint;
}

static long long get_stat_longlong(cJSON *root, char *stat_name)
{
    if (root == NULL) {
        return -1;
    }
    
    cJSON *stat = cJSON_GetObjectItem(root, stat_name);
    
    if (stat == NULL) {
        return -1;
    }
    
    return (long long)stat->valuedouble;
}

int get_twem_stats(char * ip, int port, char * pool_name)
{
    int cfd = -1;
    int i;
    int trytimes = 0, max_trytimes = 3;
    ssize_t recbytes;
    int sin_size;
    struct sockaddr_in s_add,c_adda;
    cJSON *root = NULL; 
    cJSON *pool = NULL;
    
    cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == cfd) {
        printf("socket fail: %s\n", strerror(errno));
        goto error;
    }
    
    bzero(&s_add,sizeof(struct sockaddr_in));
    s_add.sin_family=AF_INET;
    s_add.sin_addr.s_addr= inet_addr(ip);
    s_add.sin_port=htons(port);
    
    if (-1 == connect(cfd,(struct sockaddr *)(&s_add), sizeof(struct sockaddr))) {
        printf("connect fail: %s\n", strerror(errno));
        goto error;
    }
    
    if (write(cfd, "status\r\n", 8) != 8) {
        printf("write data fail\n");
        goto error;
    }
    
    content_len = 0;
tryagain:
    for (;;) {
        recbytes = read(cfd,buffer,BYTES_RECEIVE_PRE_TIME);
        if (recbytes > 0) {
        if (content == NULL) {
            content = malloc((recbytes + 1)*sizeof(char));
            if (content == NULL) {
                printf("out of memory\n");
                goto error;
            }
            content_size = recbytes + 1;
        } else if (recbytes > content_size-content_len) {
            content = realloc(content, (content_size + recbytes + 1)*sizeof(char));
            if (content == NULL) {
                printf("out of memory\n");
                goto error;
            }
            content_size += recbytes + 1;
        }
        memcpy(content+content_len, buffer, recbytes);
        content_len += recbytes;
            if (recbytes < BYTES_RECEIVE_PRE_TIME) {
                break;
            }
        } else if (recbytes == 0) {
            break;
        } else {
            printf("read data fail: %s\n", strerror(errno));
            goto error;
        }

    }
    
    content[content_len]='\0';
    root = cJSON_Parse(content);
    if (root == NULL) {
        if (trytimes >= max_trytimes) {
            printf("receive data timeout\n");
            goto error;
        }
        trytimes ++;
        goto tryagain;
    }
    pool = cJSON_GetObjectItem(root, pool_name);
    if (pool == NULL) {
        printf("pool %s can not find!\n", pool_name);
        goto error;
    }

    long long client_connections_num = get_stat_longlong(pool, "client_connections");
    stats_now[idx] = client_connections_num;
    stats[idx] = stats_now[idx] - stats_pre[idx];
    idx++;
    
    long long client_eof_num = get_stat_longlong(pool, "client_eof");
    stats_now[idx] = client_eof_num;
    stats[idx] = stats_now[idx] - stats_pre[idx];
    stats_pre[idx] = stats_now[idx];
    idx++;
    
    long long client_err_num = get_stat_longlong(pool, "client_err");
    stats_now[idx] = client_err_num;
    stats[idx] = stats_now[idx] - stats_pre[idx];
    stats_pre[idx] = stats_now[idx];
    idx++;

    long long server_ejects_num = get_stat_longlong(pool, "server_ejects");
    stats_now[idx] = server_ejects_num;
    stats[idx] = stats_now[idx] - stats_pre[idx];
    stats_pre[idx] = stats_now[idx];
    idx++;

    //5
    stats_now[idx] = 0;
    stats_now[idx + 1] = 0;
    for (i = 0; i < cJSON_GetArraySize(pool); i++) {
        int next = 0;
        cJSON *server = cJSON_GetArrayItem(pool,i);
        if (server->type != cJSON_Object) {
            continue;
        }

        long long server_connections_num = get_stat_longlong(server, "server_connections");
        stats_now[idx + next++] += server_connections_num;
        
        long long requests_num = get_stat_longlong(server, "requests");
        stats_now[idx + next++] += requests_num;

        long long request_bytes_num = get_stat_longlong(server, "request_bytes");
        stats_now[idx + next++] += request_bytes_num;

        long long responses_num = get_stat_longlong(server,"responses");
        stats_now[idx + next++] += responses_num;

        long long response_bytes_num = get_stat_longlong(server, "response_bytes");
        stats_now[idx + next++] += response_bytes_num;

        long long in_queue_num = get_stat_longlong(server, "in_queue");
        stats_now[idx + next++] += in_queue_num;

        long long out_queue_num = get_stat_longlong(server, "out_queue");
        stats_now[idx + next++] += out_queue_num;
    }
    
    //5
    stats[idx] = stats_now[idx] - stats_pre[idx];
    idx ++;
    
    //6
    stats[idx] = stats_now[idx] - stats_pre[idx];
    stats_pre[idx] = stats_now[idx];
    idx ++;
    
    //7
    stats[idx] = stats_now[idx] - stats_pre[idx];
    stats_pre[idx] = stats_now[idx];
    idx ++;
    
    //8
    stats[idx] = stats_now[idx] - stats_pre[idx];
    stats_pre[idx] = stats_now[idx];
    idx ++;
    
    //9
    stats[idx] = stats_now[idx] - stats_pre[idx];
    stats_pre[idx] = stats_now[idx];
    idx ++;
    
    //10
    stats[idx] = stats_now[idx] - stats_pre[idx];
    idx ++;
    
    //11
    stats[idx] = stats_now[idx] - stats_pre[idx];
    
    if (idx + 1 != stats_len) {
        printf("idx is error(now is %d, must be equal %d)!\n", idx, stats_len - 1);
        
        cJSON_Delete(root);
        if (cfd > 0) {
            close(cfd);
            cfd = -1;
        }
        exit(1);
    }

    if (root != NULL) {
        cJSON_Delete(root);
        root = NULL;
    }

    if (cfd > 0) {
        close(cfd);
        cfd = -1;
    }

    return 0;

error:

    if (cfd > 0) {
        close(cfd);
        cfd = -1;
    }
    if (root != NULL) {
        cJSON_Delete(root);
        root = NULL;
    }
    return -1;
}

int get_mc_get_set(char * ip, int port)
{
    int cfd;
    int recbytes;
    int sendbytes;
    int sin_size;
    char buffer[5000]={0};   
    struct sockaddr_in s_add,c_adda;

    int i;
    
    cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == cfd) {
        printf("socket fail ! \r\n");
        return -1;
    }
    
    bzero(&s_add,sizeof(struct sockaddr_in));
    s_add.sin_family=AF_INET;
    s_add.sin_addr.s_addr= inet_addr(ip);
    s_add.sin_port=htons(port);
    
    if (-1 == connect(cfd,(struct sockaddr *)(&s_add), sizeof(struct sockaddr))) {
        printf("connect fail !\r\n");
        return -1;
    }
    
    char *send_str = "stats\r\n";
    if(-1 == (sendbytes = send(cfd, send_str, strlen(send_str), 0)));
    {
        printf("write data fail : %s\r\n", strerror(errno));
        return -1;
    }

    if(-1 == (recbytes = read(cfd,buffer,5000)))
    {
        printf("read data fail !\r\n");
        return -1;
    }
    printf("read ok\r\nREC:\r\n");
    buffer[recbytes]='\0';
    close(cfd);
    return 0;
}

void print_stats()
{
    int i;
    
    time(&timer);
    tblock=localtime(&timer);
    printf("%d:%d\t", tblock->tm_min, tblock->tm_sec);
    for (i = 0; i< stats_len; i ++) {
        stats_now[i] = 0;
        printf("%lld\t", stats[i]);
    }
    printf("\n");
}

//gcc -o show_twem_stats show_twem_stats.c cJSON.c -lm
int main(int argc, char **argv)
{
    if (argc != 6 && argc != 7) {
        printf("Command error!\nUseage : show_twem_stats ip port interval(ms) loop(times|forever) pool_name [proc_id|proc_file]\n");
        exit(0);
    }

    int i;
    int counter = 0;
    char *ip = argv[1];
    int port = atoi(argv[2]);
    int interval = atoi(argv[3]);
    char *loop = argv[4];
    char *pool_name = argv[5];
    char *proc = NULL;
    
    stats_len = 11;
    
    if (argc == 7) {
        proc = argv[6];
        stats_len ++;
    }
    
    if (port <= 0) {
        printf("port must be a positive number!\n");
        exit(0);
    }

    if (interval <= 0) {
        printf("interval must be a positive number!\n");
        exit(0);
    }

    int times = atoi(loop);

    if (times <= 0 && strcmp(loop, "forever") != 0) {
        printf("loop_type must be a positive number or forever!\n");
        exit(0);
    }

    if (proc != NULL)
        idx ++;
    get_twem_stats(ip, port, pool_name);
    for (i = 0; i < stats_len; i ++) {
        stats_now[i] = 0;
    }
    usleep(interval*1000);
    
    idx = 0;
    
    i = 0;
    while (i < times || times == 0) {   
        if (counter == 0) {
            if (proc != NULL)
                printf("time  \tmem(kb)\tc_conn\tc_eof\tc_err\ts_eject\ts_conn\treq\treq_b\tresp\tresp_b\tin_q\tout_q\n");
            else
                printf("time  \tc_conn\tc_eof\tc_err\ts_eject\ts_conn\treq\treq_b\tresp\tresp_b\tin_q\tout_q\n");
        }
        
        if (counter >= content_name_interval) {
            counter = -1;
        }
        get_twem_used_memory(proc);
        get_twem_stats(ip, port, pool_name);
        print_stats();

        idx = 0;
        i ++;
        counter ++;
        usleep(interval*1000);
    }
    
    return 0;
}
