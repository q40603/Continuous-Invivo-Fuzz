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
#include <errno.h>

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
    char afl_dir[1024];
    int afl_input_fd;
    FILE* afl_input_fp;
    int afl_shm_id;
    int afl_input_location_shm_id;
    int possibility_denominator;
    int debug_level;
    struct FD_list* sk_list;
    struct FD_list* file_list;
};

extern struct BSA_info bsa_info;

#define AUTO_FUZZ 1
#define FUNCTION_FUZZ 2
#define REPORT_FUZZ 3
#define MANUAL_FUZZ 4


#define MULTI_PROCESS_MODE 1
#define MULTI_CONTAINER_MODE 0




#define INVIVO_PRIO 5
#define MAX_FD_NUM 131072
#define MAX_BB 64

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define MAP_SIZE_BIG        (1 << (MAP_SIZE_POW2*2))

#define NGRAM 64
#define SEED_DICT_SIZE 65537

#define AFL_BIND_PORT           5198

#define SHM_ENV_VAR             "__AFL_SHM_ID"

/* BSA return value */
#define BSA_SUCCESS             0
#define BSA_FAIL                1

/* BSA buf */
#define BSA_FD_MAX              1024

/* Immediate Agent Info */
#define BSA_srv_addr            "/tmp/IA.sock"//"127.0.0.1"
// #define BSA_srv_port            8001

/* status of BSA_rt */
#define BSADebugging            5
#define BSARun                  0
#define BSAFuzz                 1
#define BSAStop                 4
#define BSAPrep                 2

/* pintool channels */
#define PINTOOL_READ_FD         193
#define PINTOOL_WRITE_FD        194

/* AFL_CHANNELs */

#define FILE_SERVER_EVENT1_READ_FD     193
#define FILE_SERVER_EVENT1_WRITE_FD    194

#define FILE_SERVER_EVENT2_READ_FD     195
#define FILE_SERVER_EVENT2_WRITE_FD    196
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


/* Math */
#define MIN(x,y) ((x) < (y) ? (x) : (y)) 
#define MAX(x,y) ((x) > (y) ? (x) : (y)) 



#ifndef AFL_NGRAM_CONFIG_H
#define AFL_NGRAM_CONFIG_H

#include "types.h"

#if (MAP_SIZE_POW2 <= 16)
typedef u16 PREV_LOC_T;
#elif (MAP_SIZE_POW2 <= 32)
typedef u32 PREV_LOC_T;
#else
typedef u64 PREV_LOC_T;
#endif

/* Maximum ngram size */
#define NGRAM_SIZE_MAX 16U

/* Maximum K for top-K context sensitivity */
#define CTX_MAX_K 32U

#endif



#define BSA_err(x...)  \
    fprintf(stderr,x);      \
    perror(":");    \
    exit(1);

#define BSA_log(x...)   \
    if (bsa_info.debug_level > 0 ) printf(x); 


#endif
