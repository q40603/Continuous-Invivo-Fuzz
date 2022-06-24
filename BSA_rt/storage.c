#define _GNU_SOURCE  
#include "storage.h"
#include "config.h"
#include "utils.h"



__thread struct BSA_buf_pool* bsa_buf_pool[MAX_FD_NUM];
__thread char BSA_dump_dir[4096];
//sem_t mutex;


void BSA_init_global_buf_pool(){
    
    for(int i = 0 ; i < MAX_FD_NUM ; i++){
        bsa_buf_pool[i] = (struct BSA_buf_pool*)calloc(sizeof(struct BSA_buf_pool), 1);

        if (bsa_buf_pool[i] == NULL){
            BSA_err("Can not init buf pool\n");
        }
        bsa_buf_pool[i]->n_buf = 0;
    }

}

void BSA_init_buf_pool(int fd){
    if (bsa_buf_pool[fd])
        return;
    
    bsa_buf_pool[fd] = (struct BSA_buf_pool*)calloc(sizeof(struct BSA_buf_pool), 1);

    if (bsa_buf_pool[fd] == NULL){
        BSA_err("Can not init buf pool\n");
    }
    bsa_buf_pool[fd]->n_buf = 0;
}


void BSA_del_first(int fd){
    if(bsa_buf_pool[fd]->buf_head != NULL){
        struct BSA_buf* tmp_buf = bsa_buf_pool[fd]->buf_head;
        bsa_buf_pool[fd]->buf_head = bsa_buf_pool[fd]->buf_head->next;
        free(tmp_buf->data);
        free(tmp_buf);
        bsa_buf_pool[fd]->n_buf -= 1;
    }
}



struct BSA_buf* BSA_create_buf(int fd, size_t buf_size){
    
    //sem_wait(&mutex); 
    struct BSA_buf* buf;
    struct stat fd_stat;
    
    if (bsa_buf_pool[fd] == NULL){
        BSA_init_buf_pool(fd);
        //BSA_log("init buf\n");
    }


    /* check if it's socket */
    fstat(fd, &fd_stat);
    if (!S_ISSOCK(fd_stat.st_mode)){
        return NULL;
    }





    buf = (struct BSA_buf*)calloc(sizeof(struct BSA_buf), 1);

    if (buf == NULL){
        BSA_err("Can not alloc BSA_buf\n");
    }
    buf->data = malloc(buf_size);

    if (buf->data == NULL){
        free(buf);
        return NULL;
    }
    
    buf->len = buf_size;
    buf->_afl_edge = 0;
    
    if (bsa_buf_pool[fd]->buf_head == NULL){
        bsa_buf_pool[fd]->buf_head = buf;
    }
    else{
        bsa_buf_pool[fd]->buf_tail->next = buf;
    }
    bsa_buf_pool[fd]->buf_tail = buf;
    bsa_buf_pool[fd]->n_buf += 1;



    if(bsa_buf_pool[fd]->n_buf > 100){
        BSA_del_first(fd);
    }

    //sem_post(&mutex); 
    return buf;
}

int BSA_dump_buf(){
    struct BSA_buf* buf; 
    int out_fd;
    int count = 0;
    char *path;

    if (access(BSA_dump_dir, F_OK) !=0 && (mkdir(BSA_dump_dir, 0700) != 0)){
        BSA_err("Can not create dump directory");
    }

    /*
     * dump previous inputed data as fuzzer's seed
     */
    for(int i = 0 ; i < MAX_FD_NUM; i ++){
        if (bsa_buf_pool[i] == NULL)
            continue;

        buf = bsa_buf_pool[i]->buf_head;
        if (buf != NULL){
            while(buf){
                asprintf(&path, "%s/%d_%d", BSA_dump_dir, buf->_afl_edge, count++);
                out_fd = open(path, O_CREAT|O_RDWR, 0600);    
                BSA_log("creating testcase: %s\n", path);
                if (out_fd == -1){
                    BSA_err("Can not create testcase file")
                }
                write(out_fd, buf->data, buf->len);
                buf = buf->next;
                close(out_fd);
            }
        }        
    }

    if(count == 0){
        return -1;
    }

    BSA_clear_buf(); 

    return 0;
}

void BSA_clear_buf(){
    struct BSA_buf* buf;
    struct BSA_buf* tmp_buf;
    for(int i = 0 ; i < MAX_FD_NUM ; i++){
        if(bsa_buf_pool[i] == NULL)
            continue;

        buf = bsa_buf_pool[i]->buf_head;
        while(buf){
            tmp_buf = buf;
            buf = buf->next;
            free(tmp_buf->data);
            free(tmp_buf);
        }
        bsa_buf_pool[i]->buf_head = NULL;
        bsa_buf_pool[i]->buf_tail = NULL;
        bsa_buf_pool[i]->n_buf = 0;
    }
}


