#define _GNU_SOURCE
#include "hook.h"
#include "storage.h"
#include "config.h"

extern __thread u32 BSA_state;
extern __thread PREV_LOC_T __afl_prev_loc[NGRAM_SIZE_MAX];


#define BSA_HOOK_FUNCTION_DENY(x) \
    switch(BSA_state){  \
    case BSAFuzz:   \
        break;  \
    default:    \
        x;  \
        break;  \
    }




int BSA_hook_close(int fd){
    struct stat st;
    fstat(fd, &st);
    //if (S_ISSOCK(st.st_mode) && BSA_state == BSARun){
    if (S_ISSOCK(st.st_mode)){
        if(BSA_state == BSARun){
            BSA_log("session end\n");
        }
        else if(BSA_state == BSAFuzz){
            close(fd);
            exit(0);
        }
        
    }
    return close(fd);
}

int BSA_hook_accept(
    int socket, 
    struct sockaddr *restrict address,
    socklen_t *restrict address_len
){

    int sock_fd = accept(socket, address, address_len);
    if(sock_fd > 0)
        BSA_log("accept on fd %d\n", sock_fd);
    return sock_fd;
}


int BSA_hook_accept4(
    int socket, 
    struct sockaddr *restrict address,
    socklen_t *restrict address_len,
    int flags
){

    int sock_fd = accept4(socket, address, address_len, flags);
    if(sock_fd > 0)
        BSA_log("accept on fd %d\n", sock_fd);
    return sock_fd;
}

ssize_t BSA_hook_read(int fd, uint8_t* buf, size_t len){
    
    size_t ret;
    struct BSA_buf* dest;
    struct stat st;

    ret = read(fd, buf, len);
    
    fstat(fd, &st);
    if (S_ISSOCK(st.st_mode) && BSA_state == BSARun && ret > 0){
        BSA_log("BSA_hook_read afl_prev_loc = %d, fd = %d\n",__afl_prev_loc[0], fd );
        //BSA_log("BSA_hook_read Tid: %ld\n", syscall(__NR_gettid));
        dest = BSA_create_buf(fd, ret);
        if(dest != NULL){
            memcpy(dest->data, buf, ret);
        }
    }
    // if(BSA_state == BSAFuzz){
    //     BSA_log("fuzz-  BSA_hook_read afl_prev_loc = %d, fd = %d, ret = %ld\n",__afl_prev_loc[0], fd, ret );
    // }
    return ret;
}

ssize_t BSA_hook_recv(int sockfd, void* buf, size_t len, int flags){
    
    ssize_t ret;
    struct BSA_buf* dest;
    
    ret = recv(sockfd, buf, len, flags);
    if (BSA_state == BSARun && ret > 0){
        BSA_log("BSA_hook_recv afl_prev_loc = %d\n",__afl_prev_loc[0] );
        //BSA_log("BSA_hook_recv Tid: %ld %d\n", syscall(__NR_gettid), ret);
        dest = BSA_create_buf(sockfd, ret);
        if(dest != NULL){
            //BSA_log("%s\n", dest->data);
            memcpy(dest->data, buf, ret);
        }
    }
    return ret;
}

ssize_t BSA_hook_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
    ssize_t ret;
    struct BSA_buf* dest;

    ret = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (BSA_state == BSARun && ret > 0){
        BSA_log("BSA_hook_recvfrom Tid afl_prev_loc = %d\n", __afl_prev_loc[0] );
        //BSA_log("BSA_hook_recvfrom Tid: %ld\n", syscall(__NR_gettid));
        dest = BSA_create_buf(sockfd, ret);
        if(dest != NULL){
            memcpy(dest->data, buf, ret);
            // BSA_log("%s\n", dest->data);
            // int out_fd = open("./tmp1", O_CREAT|O_RDWR, 0777); 
            // write(out_fd, dest->data, dest->len);
            // close(out_fd);
        }
        
    }
    return ret;
}

ssize_t BSA_hook_recvmsg(int sockfd, struct msghdr *msg, int flags){
    ssize_t ret, cnt;
    struct BSA_buf* dest;
    int i = 0;
    
    cnt = ret = recvmsg(sockfd, msg, flags);
    
    if (BSA_state == BSARun && ret > 0){
        BSA_log("BSA_hook_recvmsg Tid afl_prev_loc = %d\n", __afl_prev_loc[0] );
       //BSA_log("BSA_hook_recvfrom Tid: %ld\n", syscall(__NR_gettid))
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

