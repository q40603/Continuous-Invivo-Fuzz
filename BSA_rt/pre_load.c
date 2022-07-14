#define _GNU_SOURCE
#include "hook.h"
#include "storage.h"
#include "config.h"

extern __thread u32 BSA_state;
extern u8 *BSA_entry_value_map;
extern __thread int _function_edge;
extern __thread char *function_entry_name;
extern int* afl_input_location_id;

#define BSA_HOOK_FUNCTION_DENY(x) \
    switch(BSA_state){  \
    case BSAFuzz:   \
        break;  \
    default:    \
        x;  \
        break;  \
    }


void set_src_ip(int newfd, struct BSA_buf* dest) {
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(newfd, (struct sockaddr *)&addr, &addr_size);
    sprintf(dest->ip_port, "%s_%u", inet_ntoa(addr.sin_addr), addr.sin_port);
}


ssize_t read(int fd, void * buf, size_t len){
    

    size_t ret;
    struct BSA_buf* dest;
    struct stat st;

    typedef ssize_t (*orig_type)(int fd, void * buf, size_t len);
    orig_type orig_func;
    orig_func = (orig_type)dlsym(RTLD_NEXT, "read");
    ret = orig_func(fd, buf, len);



    fstat(fd, &st);
    if (S_ISSOCK(st.st_mode) && BSA_state == BSARun && ret > 0){
        *(u8*)(BSA_entry_value_map+_function_edge) = 1;
        BSA_log("setting _function_edge %d to 1 %s\n", _function_edge, function_entry_name);
        dest = BSA_create_buf(fd, ret);
        if(dest != NULL){
            dest->_invivo_edge = _function_edge;
            memcpy(dest->data, buf, ret);
            set_src_ip(fd, dest);
        }
    }
    else if (BSA_state == BSAFuzz && ret > 0){
        if(!(*afl_input_location_id)){
            *afl_input_location_id = _function_edge;
        }
    }
    return ret;
}

ssize_t recv(int sockfd, void* buf, size_t len, int flags){
    
    ssize_t ret;
    struct BSA_buf* dest;

    typedef ssize_t (*orig_type)(int sockfd, void* buf, size_t len, int flags);
    orig_type orig_func;
    orig_func = (orig_type)dlsym(RTLD_NEXT, "recv");
    ret = orig_func(sockfd, buf, len, flags);


    if (BSA_state == BSARun && ret > 0){
        BSA_log("setting _function_edge %d to 1 %s\n", _function_edge, function_entry_name);
        *(u8*)(BSA_entry_value_map+_function_edge) = 1;
        dest = BSA_create_buf(sockfd, ret);
        if(dest != NULL){
            dest->_invivo_edge = _function_edge;
            memcpy(dest->data, buf, ret);
            set_src_ip(sockfd, dest);
        }
    }
    else if (BSA_state == BSAFuzz && ret > 0){
        if(!(*afl_input_location_id)){
            *afl_input_location_id = _function_edge;
        }
    }
    return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
    ssize_t ret;
    struct BSA_buf* dest;

    typedef ssize_t (*orig_type)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
    orig_type orig_func;
    orig_func = (orig_type)dlsym(RTLD_NEXT, "recvfrom");
    ret = orig_func(sockfd, buf, len, flags, src_addr, addrlen);

    if (BSA_state == BSARun && ret > 0){
        BSA_log("setting _function_edge %d to 1 %s\n", _function_edge, function_entry_name);
        *(u8*)(BSA_entry_value_map+_function_edge) = 1;
        dest = BSA_create_buf(sockfd, ret);
        if(dest != NULL){
            dest->_invivo_edge = _function_edge;
            memcpy(dest->data, buf, ret);
            set_src_ip(sockfd, dest);
        }
        
    }
    else if (BSA_state == BSAFuzz && ret > 0){
        if(!(*afl_input_location_id)){
            *afl_input_location_id = _function_edge;
        }
    }
    return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags){
    ssize_t ret, cnt;
    struct BSA_buf* dest;
    int i = 0;
    
    typedef ssize_t (*orig_type)(int sockfd, struct msghdr *msg, int flags);
    orig_type orig_func;
    orig_func = (orig_type)dlsym(RTLD_NEXT, "recvmsg");
    cnt = ret = orig_func(sockfd, msg, flags);
    
    if (BSA_state == BSARun && ret > 0){
        BSA_log("setting _function_edge %d to 1 %s\n", _function_edge, function_entry_name);
        *(u8*)(BSA_entry_value_map+_function_edge) = 1;
        while(cnt > 0 && i < msg->msg_iovlen){
            ssize_t len = MIN(cnt, msg->msg_iov[i].iov_len);
            dest = BSA_create_buf(sockfd, len);
            if(dest != NULL){
                dest->_invivo_edge = _function_edge;
                memcpy(dest->data, msg->msg_iov[i].iov_base, len);
                set_src_ip(sockfd, dest);
            }
            cnt -= len;
        }
    }
    else if (BSA_state == BSAFuzz && ret > 0){
        if(!(*afl_input_location_id)){
            *afl_input_location_id = _function_edge;
        }
    }
    return ret;
}

ssize_t write(int fd, const void* buf, size_t len){
    size_t ret = len;
    typedef ssize_t (*orig_type)(int fd, const void* buf, size_t len);
    orig_type orig_func;
    orig_func = (orig_type)dlsym(RTLD_NEXT, "write");
    BSA_HOOK_FUNCTION_DENY(ret = orig_func(fd,buf,len))
    return ret;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt){
    size_t ret = 0;  
    typedef ssize_t (*orig_type)(int fd, const struct iovec *iov, int iovcnt);
    orig_type orig_func;
    orig_func = (orig_type)dlsym(RTLD_NEXT, "writev");

    for(int i = 0; i < iovcnt; i++){
        ret += iov[i].iov_len;
    }
    BSA_HOOK_FUNCTION_DENY(ret = orig_func(fd, iov, iovcnt))
    return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags){
    size_t ret = len;
    typedef ssize_t (*orig_type)(int sockfd, const void *buf, size_t len, int flags);
    orig_type orig_func;
    orig_func = (orig_type)dlsym(RTLD_NEXT, "send");    
    BSA_HOOK_FUNCTION_DENY(ret = orig_func(sockfd, buf, len, flags))
    return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){
    size_t ret = len;
    typedef ssize_t (*orig_type)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
    orig_type orig_func;
    orig_func = (orig_type)dlsym(RTLD_NEXT, "sendto");      
    BSA_HOOK_FUNCTION_DENY(ret = orig_func(sockfd, buf, len, flags, dest_addr, addrlen))
    return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags){
    size_t ret = 0;

    typedef ssize_t (*orig_type)(int sockfd, const struct msghdr *msg, int flags);
    orig_type orig_func;
    orig_func = (orig_type)dlsym(RTLD_NEXT, "sendmsg");  

    for(int i = 0; i < msg->msg_iovlen; i++){
        ret += msg->msg_iov[i].iov_len;
    }
    BSA_HOOK_FUNCTION_DENY(ret = orig_func(sockfd, msg, flags))
    return ret;
}


int close(int fd){
    struct stat st;
    fstat(fd, &st);

    typedef int (*orig_type)(int fd);
    orig_type orig_func;
    orig_func = (orig_type)dlsym(RTLD_NEXT, "close");  
    //if (S_ISSOCK(st.st_mode) && BSA_state == BSARun){
    if (S_ISSOCK(st.st_mode)){
        if(BSA_state == BSARun){
            BSA_log("session end\n");
        }
        else if(BSA_state == BSAFuzz){
            orig_func(fd);
            exit(0);
        }
    }
    return orig_func(fd);
}

int accept(
    int socket, 
    struct sockaddr *restrict address,
    socklen_t *restrict address_len
){

    typedef int (*orig_type)(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
    orig_type orig_func = (orig_type)dlsym(RTLD_NEXT, "accept"); 
    int sock_fd = orig_func(socket, address, address_len);
    if(sock_fd > 0)
        BSA_log("accept on fd %d\n", sock_fd);
    return sock_fd;
}


int accept4(
    int socket, 
    struct sockaddr *restrict address,
    socklen_t *restrict address_len,
    int flags
){
    typedef int (*orig_type)(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len, int flags);
    orig_type orig_func = (orig_type)dlsym(RTLD_NEXT, "accept"); 
    int sock_fd = orig_func(socket, address, address_len, flags);
    if(sock_fd > 0)
        BSA_log("accept on fd %d\n", sock_fd);
    return sock_fd;
}


// void BSA_hook_free(void *ptr){
//     BSA_log("free tid = %ld func = %s\n",syscall(__NR_gettid), function_entry_name);
//     free(ptr);
// }

// void * BSA_hook_calloc (size_t nelem, size_t elsize){
//     BSA_log("calloc %ld tid = %ld\n", nelem, syscall(__NR_gettid));
//     return calloc(nelem, elsize);
// }

// void *BSA_hook_malloc(size_t n){
//     BSA_log("malloc %ld tid = %ld fun = %s\n", n, syscall(__NR_gettid), function_entry_name);
//     return malloc(n);
// }
// void *BSA_hook_realloc(void *ptr, size_t size){
//     BSA_log("realloc %ld tid = %ld\n", size, syscall(__NR_gettid));
//     return realloc(ptr, size);
// }

// void *BSA_hook_reallocarray(void *ptr, size_t nmemb, size_t size){
//     BSA_log("reallocarray\n");
//     return reallocarray(ptr, nmemb, size);
// }

// void *BSA_hook_memcpy (void *dest, const void *src, size_t len){
//     BSA_log("memcpy\n");
//     return memcpy(dest, src, len);
// }

// void *BSA_hook_memmove(void *dest, const void *src, size_t n){
//     BSA_log("memmove\n");
//     return memmove(dest, src, n);
// }


// void *BSA_hook_memchr(const void *s, int c, size_t n){
//     BSA_log("memchr\n");
//     return memchr(s, c, n);
// }

// void *BSA_hook_memrchr(const void *s, int c, size_t n){
//     BSA_log("memrchr\n");
//     return memrchr(s, c, n);
// }

// void *BSA_hook_rawmemchr(const void *s, int c){
//     return rawmemchr(s, c);
// }

// void *BSA_hook_memset(void *s, int c, size_t n){
//     return memset(s, c, n);
// }


// int BSA_hook_memcmp(const void *s1, const void *s2, size_t n){
//     return memcmp(s1, s2, n);
// }

// char *BSA_hook_strcpy(char *restrict dest, const char *src){
//     return strcpy(dest, src);
// }
// char *BSA_hook_strncpy(char *restrict dest, const char *restrict src, size_t n){
//     return strncpy(dest, src, n);
// }


// size_t BSA_hook_strlen(const char *s){
//     return strlen(s);
// }


// char *BSA_hook_strcat(char *restrict dest, const char *restrict src){
//     return strcat(dest, src);
// }
// char *BSA_hook_strncat(char *restrict dest, const char *restrict src, size_t n){
//     return strncat(dest, src, n);
// }

// int BSA_hook_strncmp(const char *s1, const char *s2, size_t n){
//     return strncmp(s1, s2, n);
// }
// int BSA_hook_strcmp(const char *s1, const char *s2){
//     return strcmp(s1, s2);
// }

// int BSA_hook_strcasecmp(const char *s1, const char *s2){
//     return strcasecmp(s1, s2);
// }
// int BSA_hook_strncasecmp(const char *s1, const char *s2, size_t n){
//     return strncasecmp(s1, s2, n);
// }

// size_t BSA_hook_strspn(const char *s, const char *accept){
//     return strspn(s, accept);
// }
// size_t BSA_hook_strcspn(const char *s, const char *reject){
//     return strcspn(s, reject);
// }


// int BSA_hook_strcoll(const char *s1, const char *s2){
//     return strcoll(s1, s2);
// }

// size_t BSA_hook_strxfrm(char *restrict dest, const char *restrict src, size_t n){
//     return strxfrm(dest, src, n);
// }

// char *BSA_hook_strstr(const char *haystack, const char *needle){
//     return strstr(haystack, needle);
// }

// char *BSA_hook_strcasestr(const char *haystack, const char *needle){
//     return strcasestr(haystack, needle);
// }

// char *BSA_hook_strchr(const char *s, int c){
//     return strchr(s, c);
// }
// char *BSA_hook_strrchr(const char *s, int c){
//     return strrchr(s, c);
// }
// char *BSA_hook_strpbrk(const char *s, const char *accept){
//     return strpbrk(s, accept);
// }

// char *BSA_hook_strtok(char *restrict str, const char *restrict delim){
//     return strtok(str, delim);
// }
// char *BSA_hook_strtok_r(char *restrict str, const char *restrict delim,
//                       char **restrict saveptr){
//     return strtok_r(str, delim,saveptr);
// }

