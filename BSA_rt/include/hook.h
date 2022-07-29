#ifndef _HOOK_H_
#define _HOOK_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <pthread.h>

// ssize_t BSA_hook_read(int fd, uint8_t* buf, size_t len);
// ssize_t BSA_hook_write(int fd, uint8_t* buf, size_t len);
// ssize_t BSA_hook_recv(int sockfd, void* buf, size_t len, int flags);
// int BSA_hook_close(int fd);
void incr_mem_alloc();
void incr_mem_oper();
void incr_str_oper();
void append_bbid_to_exec(int bbid);
// void log_exec_trace(int sock_fd);
// void set_src_ip(int newfd, struct BSA_buf* dest);
// ssize_t BSA_hook_read(int fd, uint8_t* buf, size_t len);
// ssize_t BSA_hook_recv(int sockfd, void* buf, size_t len, int flags);
// ssize_t BSA_hook_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
// ssize_t BSA_hook_recvmsg(int sockfd, struct msghdr *msg, int flags);
// ssize_t BSA_hook_write(int fd, const void * buf, size_t len);
// ssize_t BSA_hook_writev(int fd, const struct iovec *iov, int iovcnt);
// ssize_t BSA_hook_send(int sockfd, const void *buf, size_t len, int flags);
// ssize_t BSA_hook_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
// ssize_t BSA_hook_sendmsg(int sockfd, const struct msghdr *msg, int flags);
// int BSA_hook_close(int fd);
// int BSA_hook_accept(
//     int socket, 
//     struct sockaddr *restrict address,
//     socklen_t *restrict address_len
// );
// int BSA_hook_accept4(
//     int socket, 
//     struct sockaddr *restrict address,
//     socklen_t *restrict address_len,
//     int flags
// );
// int BSA_hook_strncmp(const char *s1, const char *s2, size_t n);
// int BSA_hook_strcmp(const char *s1, const char *s2);
// int BSA_hook_strcasecmp(const char *s1, const char *s2);
// int BSA_hook_strncasecmp(const char *s1, const char *s2, size_t n);
// size_t BSA_hook_strspn(const char *s, const char *accept);
// size_t BSA_hook_strcspn(const char *s, const char *reject);
// int BSA_hook_strcoll(const char *s1, const char *s2);
// size_t BSA_hook_strxfrm(char *restrict dest, const char *restrict src, size_t n);
// char *BSA_hook_strstr(const char *haystack, const char *needle);
// char *BSA_hook_strcasestr(const char *haystack, const char *needle);
// // void BSA_extract_dict(uint8_t *s2);
#endif
