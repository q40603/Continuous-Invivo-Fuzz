#ifndef _HOOK_H_
#define _HOOK_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

ssize_t BSA_hook_read(int fd, uint8_t* buf, size_t len);
ssize_t BSA_hook_write(int fd, uint8_t* buf, size_t len);
ssize_t BSA_hook_recv(int sockfd, void* buf, size_t len, int flags);
#endif
