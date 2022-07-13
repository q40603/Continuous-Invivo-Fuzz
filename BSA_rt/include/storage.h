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
    char ip_port[40];
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

#endif
