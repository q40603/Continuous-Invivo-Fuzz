#ifndef __UTILS_H_
#define __UTILS_H_

#include "config.h"
#include <pthread.h>

void copy_shm_pages();
int BSA_bind_socket(const char* name);
int BSA_unlink_socket(const char* name);

void BSA_sockets_handler();
void BSA_conn_IA(int, int);

void BSA_accept_channel(int* channel,const char* desc);
void BSA_afl_handshake();
void BSA_forkserver_prep();
void BSA_update_fd_list(struct FD_list**, int fd, mode_t st);

void BSA_dup_target_fd();
void BSA_clear_sk_list();
void BSA_setup_timer();

void BSA_reopen_fd();
void install_seccomp();

#endif