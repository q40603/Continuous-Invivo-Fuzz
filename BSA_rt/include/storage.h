#ifndef _STORAGE_H
#define _STORAGE_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/*
 * storing user input as afl seed
 * by hooking the 'read like' function calls
 *
 * constrainted by racing condition
 * */


struct BSA_buf{
    struct BSA_buf* next;
    uint8_t* data;
    size_t  len;
};

struct BSA_buf_pool{
    struct BSA_buf* buf_head;
    struct BSA_buf* buf_tail;
};


/* function */
void BSA_init_buf_pool();
void BSA_clear_buf();
int BSA_dump_buf();
struct BSA_buf* BSA_create_buf(int fd, size_t buf_size);

#endif
