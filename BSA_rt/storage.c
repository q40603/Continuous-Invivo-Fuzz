#define _GNU_SOURCE  
#include "storage.h"
#include "config.h"
#include "utils.h"



struct BSA_buf_pool* bsa_buf_pool[MAX_FD_NUM];
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

struct BSA_buf* BSA_get_tail_buf(int fd){
    if(fd>=0){
        return bsa_buf_pool[fd]->buf_tail;
    }
    else{
        return NULL;
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
    buf->_invivo_edge = -1;
    buf->mem_allocation = 0;
    buf->mem_operation = 0;
    buf->str_operation = 0;
    buf->exec_trace_path = -1;
    memset(buf->ip_port, '\0', sizeof(buf->ip_port));

    
    if (bsa_buf_pool[fd]->buf_head == NULL){
        bsa_buf_pool[fd]->buf_head = buf;
    }
    else{
        bsa_buf_pool[fd]->buf_tail->next = buf;
        buf->prev = bsa_buf_pool[fd]->buf_tail;
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
    char *path, *prev_path, *merge_path, *session, *prev_session;
    char ch;
    FILE *fold1, *fold2, *fnew;
    //off_t off = 0;

    if (access(BSA_dump_dir, F_OK) !=0 && (mkdir(BSA_dump_dir, 0700) != 0)){
        BSA_err("Can not create dump directory");
    }

    /*
     * dump previous inputed data as fuzzer's seed
     */
    for(int i = 0 ; i < MAX_FD_NUM; i ++){
        if (bsa_buf_pool[i] == NULL)
            continue;

        buf = bsa_buf_pool[i]->buf_tail;
        if (buf != NULL){
            prev_session = buf->ip_port;
            prev_path = NULL;
            while(buf){
                asprintf(&path, "%s/%d_%d", BSA_dump_dir, buf->_invivo_edge, count++);
                out_fd = open(path, O_CREAT|O_RDWR, 0666);  

                BSA_log("creating testcase: %s\n", path);
                if (out_fd == -1){
                    BSA_err("Can not create testcase file")
                }
                write(out_fd, buf->data, buf->len);
                close(out_fd);

                session = buf->ip_port;  
                
                
                
                
                
                if( prev_path && (strcmp(session, prev_session) == 0)){
                    asprintf(&merge_path, "%s/%d_%d", BSA_dump_dir, buf->_invivo_edge, count++);
                    fold1=fopen(path, "r");
                    fold2=fopen(prev_path, "r");
                    if(fold1==NULL || fold2==NULL)
                    {
                //		perror("Error Message ");
                        printf(" File does not exist or error in opening...!!\n");
                        exit(EXIT_FAILURE);
                    }
                    fnew=fopen(merge_path, "w");
                    if(fnew==NULL)
                    {
                //		perror("Error Message ");
                        printf(" File does not exist or error in opening...!!\n");
                        exit(EXIT_FAILURE);
                    }
                    while((ch=fgetc(fold1))!=EOF)
                    {
                        fputc(ch, fnew);
                    }
                    while((ch=fgetc(fold2))!=EOF)
                    {
                        fputc(ch, fnew);
                    }
                    //printf(" The two files merged into %s file successfully..!!\n\n", merge_path);
                    fclose(fold1);
                    fclose(fold2);
                    fclose(fnew);
                    free(prev_path);
                    prev_path = merge_path;
                }
                else{
                    prev_path = path;
                }
                prev_session = session;
                BSA_log("prev_path = %s\n prev_session = %s\n", prev_path, prev_session);
                buf = buf->prev;
                // if( prev_path && (strcmp(session, prev_session) == 0)){
                //     close(out_fd);
                //     out_fd = open(path, O_APPEND|O_RDWR, 0666); 

                //     in_fd = open(prev_path, O_RDONLY);
                //     fstat (in_fd, &stat_buf);
                //     sent = sendfile(out_fd, in_fd, 0, stat_buf.st_size);

                //     if (sent <= 0)
                //     {
                //         // Error or end of file
                //         if (sent != 0)
                //             perror("sendfile");  // Was an error, report it
                //         // break;
                //     }
                    
                //     BSA_log("copying data from %s to %s size=%ld\n", prev_path, path, stat_buf.st_size);
                //     close(in_fd);
                //     // close(out_fd);
                //     // out_fd = open(path, O_APPEND|O_RDWR, 0666); 
                // }




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