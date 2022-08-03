#ifndef _STORAGE_H
#define _STORAGE_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/sendfile.h>

/*
 * storing user input as afl seed
 * by hooking the 'read like' function calls
 *
 * constrainted by racing condition
 * */


struct BSA_buf{
    struct BSA_buf* next;
    struct BSA_buf *prev;
    uint8_t* data;
    size_t  len;
    int _invivo_edge;
    int mem_allocation;
    int mem_operation;
    int str_operation;
    int exec_trace_path;
    char ip_port[40];
};

struct BSA_seed_list{
    int exec_trace_path;
    float mem_allocation;
    float mem_operation;
    float str_operation;
    int code_coverage;
    int unique_crash;
    struct BSA_seed_list* next;
};

struct BSA_seed_map{
    ssize_t seed_count;
    struct BSA_seed_list* seed_head;
    struct BSA_seed_list* seed_tail;
};



struct BSA_seed_dict{
    int exist;
    char *token;
};




struct BSA_buf_pool{
    struct BSA_buf* buf_head;
    struct BSA_buf* buf_tail;
    ssize_t n_buf;
};


/* function */
void BSA_init_global_buf_pool();
void BSA_init_buf_pool(int fd);
void BSA_clear_buf();
void BSA_del_first(int fd);
int BSA_dump_buf();
struct BSA_buf* BSA_create_buf(int fd, size_t buf_size);
struct BSA_buf* BSA_get_tail_buf(int fd);

#endif
