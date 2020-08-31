#include "hook.h"
#include "storage.h"
#include "config.h"

extern __thread u32 BSA_state;


#define BSA_HOOK_FUNCTION_DENY(x) \
    switch(BSA_state){  \
    case BSAFuzz:   \
        break;  \
    default:    \
        x;  \
        break;  \
    }

ssize_t BSA_hook_read(int fd, uint8_t* buf, size_t len){
    
    size_t ret;
    struct BSA_buf* dest;
    struct stat st;

    ret = read(fd, buf, len);
    
    fstat(fd, &st);
    if (S_ISSOCK(st.st_mode) && BSA_state == BSARun && ret > 0){
        //BSA_log("Tid: %ld\n", syscall(__NR_gettid))
        dest = BSA_create_buf(fd, ret);
        if(dest != NULL){
            memcpy(dest->data, buf, ret);
        }
    }
    return ret;
}

ssize_t BSA_hook_recv(int sockfd, void* buf, size_t len, int flags){
    
    ssize_t ret;
    struct BSA_buf* dest;
    
    ret = recv(sockfd, buf, len, flags);
    if (BSA_state == BSARun && ret > 0){
        //BSA_log("Tid: %ld\n", syscall(__NR_gettid))
        dest = BSA_create_buf(sockfd, ret);
        if(dest != NULL){
            memcpy(dest->data, buf, ret);
        }
    }
    return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
    ssize_t ret;
    struct BSA_buf* dest;

    ret = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (BSA_state == BSARun && ret > 0){
        //BSA_log("Tid: %ld\n", syscall(__NR_gettid))
        dest = BSA_create_buf(sockfd, ret);
        if(dest != NULL){
            memcpy(dest->data, buf, ret);
        }
    }
    return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags){
    ssize_t ret, cnt;
    struct BSA_buf* dest;
    int i = 0;
    
    cnt = ret = recvmsg(sockfd, msg, flags);
    
    if (BSA_state == BSARun && ret > 0){
        //BSA_log("Tid: %ld\n", syscall(__NR_gettid))
        while(cnt > 0 && i < msg->msg_iovlen){
            ssize_t len = MIN(cnt, msg->msg_iov[i].iov_len);
            dest = BSA_create_buf(sockfd, len);
            if(dest != NULL){
                memcpy(dest->data, msg->msg_iov[i].iov_base, len);
            }
            cnt -= len;
        }
    }
    return ret;
}

ssize_t BSA_hook_write(int fd, uint8_t* buf, size_t len){
    size_t ret = len;
    BSA_HOOK_FUNCTION_DENY(ret=write(fd,buf,len))
    return ret;
}

ssize_t BSA_hook_writev(int fd, const struct iovec *iov, int iovcnt){
    size_t ret = 0;
    for(int i = 0; i < iovcnt; i++){
        ret += iov[i].iov_len;
    }
    BSA_HOOK_FUNCTION_DENY(ret = writev(fd, iov, iovcnt))
    return ret;
}

ssize_t BSA_hook_send(int sockfd, const void *buf, size_t len, int flags){
    size_t ret = len;
    BSA_HOOK_FUNCTION_DENY(ret = send(sockfd, buf, len, flags))
    return ret;
}

ssize_t BSA_hook_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){
    size_t ret = len;
    BSA_HOOK_FUNCTION_DENY(ret = sendto(sockfd, buf, len, flags, dest_addr, addrlen))
    return ret;
}

ssize_t BSA_hook_sendmsg(int sockfd, const struct msghdr *msg, int flags){
    size_t ret = 0;
    for(int i = 0; i < msg->msg_iovlen; i++){
        ret += msg->msg_iov[i].iov_len;
    }
    BSA_HOOK_FUNCTION_DENY(ret = sendmsg(sockfd, msg, flags))
    return ret;
}

