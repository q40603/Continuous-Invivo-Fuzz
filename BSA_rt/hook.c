#include "hook.h"
#include "storage.h"
#include "config.h"

extern __thread u32 BSA_state;

ssize_t BSA_hook_read(int fd, uint8_t* buf, size_t len){
    
    size_t ret;
    struct BSA_buf* dest;
    struct stat st;

    ret = read(fd, buf, len);
    
    fstat(fd, &st);
    if (S_ISSOCK(st.st_mode) && BSA_state == BSARun && ret > 0){
        BSA_log("Tid: %ld\n", syscall(__NR_gettid))
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
        dest = BSA_create_buf(sockfd, ret);
        if(dest != NULL){
            memcpy(dest->data, buf, ret);
            printf("oh!! hooking recv!, %d\n", sockfd);
        }
    }
    return ret;
}

ssize_t BSA_hook_write(int fd, uint8_t* buf, size_t len){
    
    size_t ret = len;
    switch(BSA_state){

    case BSAFuzz:
        break;
    default:
        ret = write(fd, buf, len);
        break;
    }
    return ret;
}

ssize_t BSA_hook_writev(int fd, const struct iovec *iov, int iovcnt){
    
    size_t ret = iovcnt;
    switch(BSA_state){

    case BSAFuzz:
        break;
    default:
        ret = writev(fd, iov, iovcnt);
        break;
    }
    return ret;
}
