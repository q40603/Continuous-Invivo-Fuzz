#define _GNU_SOURCE
#include "hook.h"
#include "storage.h"
#include "config.h"

extern __thread u32 BSA_state;
extern u8 *BSA_entry_value_map;
extern int* afl_input_location_id;
extern __thread int _invivo_edge;
extern __thread int _function_edge;
extern __thread char *function_entry_name;

extern struct BSA_seed_map Invivo_entry_seed_map[MAP_SIZE];
extern struct BSA_buf_pool* bsa_buf_pool[MAX_FD_NUM];
extern struct BSA_seed_dict Invivo_seed_dict[SEED_DICT_SIZE];

__thread PREV_LOC_T Invivo_exec_path[NGRAM];
__thread PREV_LOC_T Invivo_exec_path_idx = 0;
__thread int cur_fd = -1;

#define BSA_HOOK_FUNCTION_DENY(x) \
    switch(BSA_state){  \
    case BSAFuzz:   \
        break;  \
    default:    \
        x;  \
        break;  \
    }

void select_entry(){
    int target_path = -1;
    int target_seed = -1;

    int min_entry_fuzz_count = 10000;
    int min_entry_seed_count = 10000;
    

    for(int i = 0 ; i < MAP_SIZE ; i++){
        if(Invivo_entry_seed_map[i].fuzz_count <= min_entry_fuzz_count) 
        {
            target_path = i;
            min_entry_fuzz_count = Invivo_entry_seed_map[i].fuzz_count;
            min_entry_seed_count = Invivo_entry_seed_map[i].seed_count;
        }
    }   
    for(int i = 0 ; i < MAP_SIZE ; i++){
        if(
            (Invivo_entry_seed_map[i].fuzz_count <= min_entry_fuzz_count) &&
            (Invivo_entry_seed_map[i].seed_count <= min_entry_seed_count))
        {
            target_path = i;
            min_entry_fuzz_count = Invivo_entry_seed_map[i].fuzz_count;
            min_entry_seed_count = Invivo_entry_seed_map[i].seed_count;
        }
    }

    if(target_path == -1){
        BSA_log("something went wrong, no entries found");
    }


    int min_seed_fuzz_count = 10000;
    int max_seed_sensitive_count = 0;
    int max_seed_fuzz_coverage = 0;
    int max_seed_fuzz_crash = 0;
    struct BSA_seed_list *seed_info_node;
    seed_info_node = Invivo_entry_seed_map[target_path].seed_head;
    while(seed_info_node){
        if( (seed_info_node->fuzz_count <= min_seed_fuzz_count) &&
            (seed_info_node->sensitive_count >= max_seed_sensitive_count) && 
            (seed_info_node->unique_crash >= max_seed_fuzz_crash) && 
            (seed_info_node->code_coverage >= max_seed_fuzz_coverage))
        {
            target_seed = seed_info_node->exec_trace_path;
        }
        seed_info_node = seed_info_node->next;
    }
    if(target_seed == -1){
        BSA_log("something went wrong, no seeds found in path %d\n", target_path);
    }
}


void update_reward(int path, int exec_trace, int val){
    struct BSA_seed_list *seed_info_node;
    int in_seed_map = 0;
    if(Invivo_entry_seed_map[path].seed_count == 0){
        BSA_log("reward : path not exists, please check;\n");
        return;
    }
    seed_info_node = Invivo_entry_seed_map[path].seed_head;
    while(seed_info_node){
        if(seed_info_node->exec_trace_path == exec_trace){
            in_seed_map = 1;
            break;
        }
        seed_info_node = seed_info_node->next;
    }    
    if(!in_seed_map){
        BSA_log("reward : exec_trace not exists, please check;\n");
        return;
    }
    seed_info_node->code_coverage = MAX(seed_info_node->code_coverage, val);
    seed_info_node->unique_crash = MAX(seed_info_node->unique_crash, val);
    Invivo_entry_seed_map[path].fuzz_count++;
}

void update_seed_map(int fd){
    if(fd == -1){
        return;
    }
    
    struct BSA_buf* buf; 
    struct BSA_seed_list *seed_info_node;
    char *session, *prev_session;
    int in_seed_map = 0;
    int cur_exec_trace = 0;
    if (bsa_buf_pool[fd] == NULL){
        
        return;
    }
        
    
    buf = bsa_buf_pool[fd]->buf_tail;
    if (buf == NULL){
        return;
    }
        

    prev_session = buf->ip_port;

    while(buf){
        session = buf->ip_port;
        if(strcmp(prev_session, session) != 0)
            break;
        // cur_exec_trace = cur_exec_trace ^ buf->exec_trace_path;
        // buf->exec_trace_path = cur_exec_trace;
        seed_info_node = Invivo_entry_seed_map[buf->_invivo_edge].seed_head;
        in_seed_map = 0;
        while(seed_info_node){
            if(seed_info_node->exec_trace_path == buf->exec_trace_path){
                seed_info_node->sensitive_count = ((float)buf->sensitive_count + seed_info_node->sensitive_count) / 2;
                in_seed_map = 1;

                // BSA_log("  path = %d\n", buf->_invivo_edge);
                // BSA_log("  seed = %d\n", buf->exec_trace_path);
                // BSA_log("  sense = %f\n\n", seed_info_node->sensitive_count);

                break;
            }
            seed_info_node = seed_info_node->next;
        }
        if(!in_seed_map){
            // BSA_log("  path = %d\n", buf->_invivo_edge);
            // BSA_log("  seed = %d\n", buf->exec_trace_path);
            // BSA_log("  sense = %d\n\n", buf->sensitive_count);
            struct BSA_seed_list * tmp_seed_node;
            tmp_seed_node = (struct BSA_seed_list*)calloc(sizeof(struct BSA_seed_list), 1);
            tmp_seed_node->exec_trace_path = buf->exec_trace_path;
            tmp_seed_node->sensitive_count = (float)buf->sensitive_count;
            tmp_seed_node->code_coverage = 0;
            tmp_seed_node->unique_crash = 0;
            tmp_seed_node->fuzz_count = 0;
            if(Invivo_entry_seed_map[buf->_invivo_edge].seed_head == NULL){
                Invivo_entry_seed_map[buf->_invivo_edge].seed_head = tmp_seed_node;
            }
            else{
                Invivo_entry_seed_map[buf->_invivo_edge].seed_tail->next = tmp_seed_node;
            }
            Invivo_entry_seed_map[buf->_invivo_edge].seed_tail = tmp_seed_node;
            Invivo_entry_seed_map[buf->_invivo_edge].seed_count ++;
        }
        buf = buf->prev;
    }
}

void append_bbid_to_exec(int bbid){
    Invivo_exec_path[(Invivo_exec_path_idx++)%NGRAM] = bbid;
}

void incr_sensitive_count(){
    struct BSA_buf* dest;
    if(cur_fd >= 0 ){
        dest = BSA_get_tail_buf(cur_fd);
        if(dest != NULL){
            dest->sensitive_count ++;
        }
    }
}
// void incr_mem_oper(){
//     struct BSA_buf* dest;
//     if(cur_fd >= 0 ){
//         dest = BSA_get_tail_buf(cur_fd);
//         if(dest != NULL){
//             dest->mem_operation ++;
//         }
//     }
// }

// void incr_str_oper(){
//     struct BSA_buf* dest;
//     if(cur_fd >= 0){
//         dest = BSA_get_tail_buf(cur_fd);
//         if(dest != NULL){
//             dest->str_operation ++;
//         }
//     }   
// }

int rolling_hash(const char *s, int n){
    const int p = 53, m = SEED_DICT_SIZE;
    int hash = 0;
    long p_pow = 1;
    for(int i = 0; i < n; i++) {
        hash = (hash + (s[i] - 'a' + 1) * p_pow) % m;
        p_pow = (p_pow * p) % m;
    }
    return hash; 
}

void BSA_extract_dict(const char * str){
    if(BSA_state != BSARun) return;
    int n = strlen(str);
    int hashed_val = rolling_hash(str, n);
    if(!Invivo_seed_dict[hashed_val].exist){
        BSA_log("str = %s dict  created\n", str);
        Invivo_seed_dict[hashed_val].token = (char *)malloc(n+1);
        strcpy(Invivo_seed_dict[hashed_val].token, str);
        Invivo_seed_dict[hashed_val].exist = 1;
    }
}

void reset_exec_trace(int fd){
    if(BSA_state != BSARun) return;
    cur_fd = fd;
    memset(Invivo_exec_path, 0 , sizeof(Invivo_exec_path));
    Invivo_exec_path_idx = 0;
}

void update_prev_exec_trace(int fd){
    if(cur_fd != fd)
        return;

    char cur_ip_port[40];
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getpeername(fd, (struct sockaddr *)&addr, &addr_size);
    if(res == 0){
        sprintf(cur_ip_port, "%s_%u", inet_ntoa(addr.sin_addr), addr.sin_port);
    }
    struct BSA_buf* dest;
    dest = BSA_get_tail_buf(cur_fd);
    if(dest != NULL){
        if(strcmp(dest->ip_port, cur_ip_port) != 0){
            return;
        }
        if(dest->finish_trace) return;
        int exec_xor_path = 0 ;
        for(int i = 0 ; i < NGRAM ; i++)
            exec_xor_path ^= Invivo_exec_path[i];
        dest->exec_trace_path = exec_xor_path;
        dest->finish_trace = 1;

        BSA_log("  path = %d\n", dest->_invivo_edge);
        BSA_log("  seed = %d\n", dest->exec_trace_path);
        BSA_log("  sense = %d\n\n", dest->sensitive_count);

    }

    //BSA_log("  ip_port = %s\n", dest->ip_port);
    // BSA_log("  path = %d\n", dest->_invivo_edge);
    // BSA_log("  seed = %d\n", dest->exec_trace_path);
    // BSA_log("  sense = %d\n", dest->sensitive_count);
    // BSA_log("  mem_alloc = %d\n", dest->mem_allocation);
    // BSA_log("  mem_oper = %d\n", dest->mem_operation);
    // BSA_log("  str_oper = %d\n", dest->str_operation);
}

void log_exec_trace(){
    struct BSA_buf* dest;
    if(cur_fd >= 0){
        dest = BSA_get_tail_buf(cur_fd);
        if(dest != NULL){
            if(dest->finish_trace) return;
            int exec_xor_path = 0 ;
            for(int i = 0 ; i < NGRAM ; i++)
                exec_xor_path ^= Invivo_exec_path[i];
            dest->exec_trace_path = exec_xor_path;
            dest->finish_trace = 1;
            BSA_log("  path = %d\n", dest->_invivo_edge);
            BSA_log("  seed = %d\n", dest->exec_trace_path);
            BSA_log("  sense = %d\n\n", dest->sensitive_count);            
        }
        // BSA_log("  ip_port = %s\n", dest->ip_port);
        // BSA_log("  _invivo_edge = %d\n", dest->_invivo_edge);
        // BSA_log("  exec_trace_path = %d\n", dest->exec_trace_path);
        // BSA_log("  mem_alloc = %d\n", dest->mem_allocation);
        // BSA_log("  mem_oper = %d\n", dest->mem_operation);
        // BSA_log("  str_oper = %d\n", dest->str_operation);
    }     
}

void set_src_ip(int newfd, struct BSA_buf* dest) {
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getpeername(newfd, (struct sockaddr *)&addr, &addr_size);
    if(res == 0){
        
        sprintf(dest->ip_port, "%s_%u", inet_ntoa(addr.sin_addr), addr.sin_port);
        //BSA_log("ip_port = %s\n", dest->ip_port);
    }
}


ssize_t BSA_hook_read(int fd, uint8_t* buf, size_t len){
    
    size_t ret;
    struct BSA_buf* dest;
    struct stat st;

    ret = read(fd, buf, len);
    
    fstat(fd, &st);
    if (S_ISSOCK(st.st_mode) && BSA_state == BSARun && ret > 0){
        *(u8*)(BSA_entry_value_map+_function_edge) = 1;
        BSA_log("fd = %d cur_fd = %d setting _function_edge %d to 1 %s\n", fd, cur_fd, _function_edge, function_entry_name);
        // if(fd != cur_fd) update_seed_map(cur_fd);
        update_prev_exec_trace(fd);
        reset_exec_trace(fd);
        dest = BSA_create_buf(fd, ret);
        if(dest != NULL){
            dest->_invivo_edge = _function_edge;
            memcpy(dest->data, buf, ret);
            set_src_ip(fd, dest);
        }
    }
    // else if (BSA_state == BSAFuzz && ret > 0){
    //     if(!(*afl_input_location_id)){
    //         *afl_input_location_id = _function_edge;
    //     }
    // }
    return ret;
}

ssize_t BSA_hook_recv(int sockfd, void* buf, size_t len, int flags){
    
    ssize_t ret;
    struct BSA_buf* dest;
    struct stat st;
    fstat(sockfd, &st);
    
    ret = recv(sockfd, buf, len, flags);

    
    if (S_ISSOCK(st.st_mode) && BSA_state == BSARun && ret > 0){
        *(u8*)(BSA_entry_value_map+_function_edge) = 1;
        BSA_log("fd = %d cur_fd = %d setting _function_edge %d to 1 %s\n", sockfd, cur_fd, _function_edge, function_entry_name);
        //if(sockfd != cur_fd) update_seed_map(cur_fd);
        update_prev_exec_trace(sockfd);
        reset_exec_trace(sockfd);
        dest = BSA_create_buf(sockfd, ret);
        if(dest != NULL){
            dest->_invivo_edge = _function_edge;
            memcpy(dest->data, buf, ret);
            set_src_ip(sockfd, dest);
        }
    }
    // else if (BSA_state == BSAFuzz && ret > 0){
    //     if(!(*afl_input_location_id)){
    //         *afl_input_location_id = _function_edge;
    //     }
    // }
    return ret;
}

ssize_t BSA_hook_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
    ssize_t ret;
    struct BSA_buf* dest;
    struct stat st;
    fstat(sockfd, &st);
    ret = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (S_ISSOCK(st.st_mode) && BSA_state == BSARun && ret > 0){
        *(u8*)(BSA_entry_value_map+_function_edge) = 1;
        BSA_log("fd = %d cur_fd = %d setting _function_edge %d to 1 %s\n", sockfd, cur_fd, _function_edge, function_entry_name);
        //if(sockfd != cur_fd) update_seed_map(cur_fd);
        update_prev_exec_trace(sockfd);
        reset_exec_trace(sockfd);
        dest = BSA_create_buf(sockfd, ret);
        if(dest != NULL){
            dest->_invivo_edge = _function_edge;
            memcpy(dest->data, buf, ret);
            set_src_ip(sockfd, dest);
        }
    }
    // else if (BSA_state == BSAFuzz && ret > 0){
    //     if(!(*afl_input_location_id)){
    //         *afl_input_location_id = _function_edge;
    //     }
    // }
    return ret;
}

ssize_t BSA_hook_recvmsg(int sockfd, struct msghdr *msg, int flags){
    ssize_t ret, cnt;
    struct BSA_buf* dest;
    int i = 0;

    struct stat st;
    fstat(sockfd, &st);
    cnt = ret = recvmsg(sockfd, msg, flags);
    
    if (S_ISSOCK(st.st_mode) && BSA_state == BSARun && ret > 0){
        *(u8*)(BSA_entry_value_map+_function_edge) = 1;
        BSA_log("fd = %d cur_fd = %d setting _function_edge %d to 1 %s\n", sockfd, cur_fd, _function_edge, function_entry_name);
        //if(sockfd != cur_fd) update_seed_map(cur_fd);
        update_prev_exec_trace(sockfd);
        reset_exec_trace(sockfd);
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
    // else if (BSA_state == BSAFuzz && ret > 0){
    //     if(!(*afl_input_location_id)){
    //         *afl_input_location_id = _function_edge;
    //     }
    // }
    return ret;
}

ssize_t BSA_hook_write(int fd, const void * buf, size_t len){
    size_t ret = len;
    struct stat st;
    fstat(fd, &st);
    if S_ISSOCK(st.st_mode){
        if(BSA_state == BSARun && ret > 0){
            log_exec_trace();
            if(fd != cur_fd) update_seed_map(cur_fd);
            
        }
        else{
            exit(0);
        }
    }
    
    BSA_HOOK_FUNCTION_DENY(ret=write(fd,buf,len))
    return ret;
}

ssize_t BSA_hook_writev(int fd, const struct iovec *iov, int iovcnt){
    size_t ret = 0;
    struct stat st;
    fstat(fd, &st);

    for(int i = 0; i < iovcnt; i++){
        ret += iov[i].iov_len;
    }

    if S_ISSOCK(st.st_mode){
        if(BSA_state == BSARun && ret > 0){
            log_exec_trace();
            if(fd != cur_fd) update_seed_map(cur_fd);
            
        }
        else{
            exit(0);
        }
    }

    BSA_HOOK_FUNCTION_DENY(ret = writev(fd, iov, iovcnt))
    return ret;
}

ssize_t BSA_hook_send(int sockfd, const void *buf, size_t len, int flags){
    size_t ret = len;
    struct stat st;
    fstat(sockfd, &st);
    if S_ISSOCK(st.st_mode){
        if(BSA_state == BSARun && ret > 0){
            log_exec_trace();
            if(sockfd != cur_fd) update_seed_map(cur_fd);
            
        }
        else{
            exit(0);
        }
    }
    BSA_HOOK_FUNCTION_DENY(ret = send(sockfd, buf, len, flags))
    return ret;
}

ssize_t BSA_hook_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){
    size_t ret = len;
    struct stat st;
    fstat(sockfd, &st);
    if S_ISSOCK(st.st_mode){
        if(BSA_state == BSARun && ret > 0){
            log_exec_trace();
            if(sockfd != cur_fd) update_seed_map(cur_fd);
            
        }
        else{
            exit(0);
        }
    }
    BSA_HOOK_FUNCTION_DENY(ret = sendto(sockfd, buf, len, flags, dest_addr, addrlen))
    return ret;
}

ssize_t BSA_hook_sendmsg(int sockfd, const struct msghdr *msg, int flags){
    size_t ret = 0;
    struct stat st;
    fstat(sockfd, &st);

    for(int i = 0; i < msg->msg_iovlen; i++){
        ret += msg->msg_iov[i].iov_len;
    }


    if S_ISSOCK(st.st_mode){
        if(BSA_state == BSARun && ret > 0){
            log_exec_trace();
            if(sockfd != cur_fd) update_seed_map(cur_fd);
        }
        else{
            exit(0);
        }
    }

    BSA_HOOK_FUNCTION_DENY(ret = sendmsg(sockfd, msg, flags))
    return ret;
}


int BSA_hook_close(int fd){
    struct stat st;
    fstat(fd, &st);
    if (S_ISSOCK(st.st_mode)){
        if(BSA_state == BSARun){
            //BSA_log("session end\n");
            log_exec_trace();
            update_seed_map(fd);
            cur_fd = -1;
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
    _invivo_edge = 0;
    // if(BSA_state == BSARun && sock_fd > 0)
    //     BSA_log("accept on fd %d\n", sock_fd);
    return sock_fd;
}


int BSA_hook_accept4(
    int socket, 
    struct sockaddr *restrict address,
    socklen_t *restrict address_len,
    int flags
){

    int sock_fd = accept4(socket, address, address_len, flags);
    _invivo_edge = 0;
    // if(BSA_state == BSARun && sock_fd > 0)
    //     BSA_log("accept on fd %d\n", sock_fd);
    return sock_fd;
}


// void BSA_hook_free(void *ptr){
//     //BSA_log("free tid = %ld func = %s\n",syscall(__NR_gettid), function_entry_name);
//     incr_mem_alloc();
//     free(ptr);
// }

// void * BSA_hook_calloc (size_t nelem, size_t elsize){
//     //BSA_log("calloc %ld tid = %ld\n", nelem, syscall(__NR_gettid));
//     incr_mem_alloc();
//     return calloc(nelem, elsize);
// }

// void *BSA_hook_malloc(size_t n){
//     //BSA_log("malloc %ld tid = %ld fun = %s\n", n, syscall(__NR_gettid), function_entry_name);
//     incr_mem_alloc();
//     return malloc(n);
// }
// void *BSA_hook_realloc(void *ptr, size_t size){
//     //BSA_log("realloc %ld tid = %ld\n", size, syscall(__NR_gettid));
//     incr_mem_alloc();
//     return realloc(ptr, size);
// }

// void *BSA_hook_reallocarray(void *ptr, size_t nmemb, size_t size){
//     //BSA_log("reallocarray\n");
//     incr_mem_alloc();
//     return reallocarray(ptr, nmemb, size);
// }

// void *BSA_hook_memcpy (void *dest, const void *src, size_t len){
//     //BSA_log("memcpy\n");
//     incr_mem_oper();
//     return memcpy(dest, src, len);
// }

// void *BSA_hook_memmove(void *dest, const void *src, size_t n){
//     //BSA_log("memmove\n");
//     incr_mem_oper();
//     return memmove(dest, src, n);
// }


// void *BSA_hook_memchr(const void *s, int c, size_t n){
//     //BSA_log("memchr\n");
//     incr_mem_oper();
//     return memchr(s, c, n);
// }

// void *BSA_hook_memrchr(const void *s, int c, size_t n){
//     //BSA_log("memrchr\n");
//     incr_mem_oper();
//     return memrchr(s, c, n);
// }

// void *BSA_hook_rawmemchr(const void *s, int c){
//     incr_mem_oper();
//     return rawmemchr(s, c);
// }

// void *BSA_hook_memset(void *s, int c, size_t n){
//     incr_mem_oper();
//     return memset(s, c, n);
// }


// int BSA_hook_memcmp(const void *s1, const void *s2, size_t n){
//     incr_mem_oper();
//     return memcmp(s1, s2, n);
// }

// char *BSA_hook_strcpy(char *restrict dest, const char *src){
//     incr_str_oper();
//     return strcpy(dest, src);
// }
// char *BSA_hook_strncpy(char *restrict dest, const char *restrict src, size_t n){
//     incr_str_oper();
//     return strncpy(dest, src, n);
// }


// size_t BSA_hook_strlen(const char *s){

//     incr_str_oper();
//     return strlen(s);
// }


// char *BSA_hook_strcat(char *restrict dest, const char *restrict src){
//     incr_str_oper();
//     return strcat(dest, src);
// }
// char *BSA_hook_strncat(char *restrict dest, const char *restrict src, size_t n){
//     incr_str_oper();
//     return strncat(dest, src, n);
// }

int BSA_hook_strncmp(const char *s1, const char *s2, size_t n){
    if(cur_fd >= 0) BSA_extract_dict(s2);
    return strncmp(s1, s2, n);
}
int BSA_hook_strcmp(const char *s1, const char *s2){
    if(cur_fd >= 0) BSA_extract_dict(s2);
    return strcmp(s1, s2);
}

int BSA_hook_strcasecmp(const char *s1, const char *s2){
    if(cur_fd >= 0) BSA_extract_dict(s2);
    return strcasecmp(s1, s2);
}
int BSA_hook_strncasecmp(const char *s1, const char *s2, size_t n){
    if(cur_fd >= 0) BSA_extract_dict(s2);
    return strncasecmp(s1, s2, n);
}

size_t BSA_hook_strspn(const char *s, const char *accept){
    if(cur_fd >= 0) BSA_extract_dict(accept);
    return strspn(s, accept);
}
size_t BSA_hook_strcspn(const char *s, const char *reject){
    if(cur_fd >= 0) BSA_extract_dict(reject);
    return strcspn(s, reject);
}


int BSA_hook_strcoll(const char *s1, const char *s2){
    if(cur_fd >= 0) BSA_extract_dict(s2);
    return strcoll(s1, s2);
}

size_t BSA_hook_strxfrm(char *restrict dest, const char *restrict src, size_t n){
    if(cur_fd >= 0) BSA_extract_dict(src);
    return strxfrm(dest, src, n);
}

char *BSA_hook_strstr(const char *haystack, const char *needle){
    if(cur_fd >= 0) BSA_extract_dict(needle);
    return strstr(haystack, needle);
}

char *BSA_hook_strcasestr(const char *haystack, const char *needle){
    if(cur_fd >= 0) BSA_extract_dict(needle);
    return strcasestr(haystack, needle);
}

char *BSA_hook_strpbrk(const char *s, const char *accept){
    if(cur_fd >= 0) BSA_extract_dict(accept);
    return strpbrk(s, accept);
}

char *BSA_hook_strtok(char *restrict str, const char *restrict delim){
    if(cur_fd >= 0) BSA_extract_dict(delim);
    return strtok(str, delim);
}
char *BSA_hook_strtok_r(char *restrict str, const char *restrict delim,
                      char **restrict saveptr){
    if(cur_fd >= 0) BSA_extract_dict(delim);
    return strtok_r(str, delim,saveptr);
}


// char *BSA_hook_strchr(const char *s, int c){
//     incr_str_oper();
//     if(cur_fd >= 0) BSA_log("strchr %c\n", c);
//     return strchr(s, c);
// }
// char *BSA_hook_strrchr(const char *s, int c){
//     incr_str_oper();
//     return strrchr(s, c);
// }




