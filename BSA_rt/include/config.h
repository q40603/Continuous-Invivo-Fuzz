#ifndef _CONFIG_H_
#define _CONFIG_H_

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <dirent.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/un.h>
#include <assert.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>


#define AFL_BIND_PORT           5198

#define SHM_ENV_VAR             "__AFL_SHM_ID"

/* BSA return value */
#define BSA_SUCCESS             0
#define BSA_FAIL                1

/* BSA buf */
#define BSA_FD_MAX              1024

/* Immediate Agent Info */
#define BSA_srv_addr            "127.0.0.1"
#define BSA_srv_port            8001

/* status of BSA_rt */
#define BSADebugging            5
#define BSARun                  0
#define BSAFuzz                 1
#define BSAStop                 4

/* pintool channels */
#define PINTOOL_READ_FD         193
#define PINTOOL_WRITE_FD        194

/* AFL_CHANNELs */
#define FILE_SERVER_READ_FD     195
#define FILE_SERVER_WRITE_FD    196
#define HANDSHAKE_CHANNEL_FD    197
#define CTL_CHANNEL_FD          198
#define STS_CHANNEL_FD          199

#define BSA_SHADOW_FD           1024
#define BSA_SHADOW_FD_MAX       2048

/* BSA docker supported! not implemented */
#define BSA_NON_DOCKER_MODE     0
#define BSA_DOCKER_MASTER       1
#define BSA_DOCKER_SLAVE        2

/* BSA FLAGS */
#define BSA_ENTRY               0b01
#define BSA_SYMBOLIC            0b10

#ifndef BSA_FUZZ_THRESHOLD  
#define BSA_FUZZ_THRESHOLD  9
#endif

/* Type Definition */
typedef uint8_t     u8;
typedef uint32_t    u32;
typedef uint64_t    u64;

#define BSA_err(x...)  \
    perror(x);      \
    exit(1);

#define BSA_log(x...)   \
    printf(x);   \

struct FD_node{
    struct  FD_node* next;
    int     fd;
    mode_t  st_mode;
};

struct FD_list{
    struct FD_node* head;
    struct FD_node* tail;
    
};

struct BSA_info{
    int pid;
    int master_pid;
    time_t start_time;
    int criu_fd;
    int afl_handshake_fd;
    int afl_sts_fd;
    int afl_ctl_fd;
    char* afl_dir;
    int afl_input_fd;
    FILE* afl_input_fp;
    int afl_shm_id;
    int possibility_denominator;
    struct FD_list* sk_list;
    struct FD_list* file_list;
};

#endif