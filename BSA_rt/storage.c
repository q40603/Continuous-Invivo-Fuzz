#include "storage.h"
#include "config.h"
#include "utils.h"

__thread struct BSA_buf_pool* bsa_buf_pool = NULL;
__thread char BSA_dump_dir[4096];

void BSA_init_buf_pool(){
    if (bsa_buf_pool)
        return;
    
    bsa_buf_pool = (struct BSA_buf_pool*)calloc(sizeof(struct BSA_buf_pool), 1);

    if (bsa_buf_pool == NULL){
        BSA_err("Can not init buf pool\n");
    }
}

struct BSA_buf* BSA_create_buf(int fd, size_t buf_size){
    
    struct BSA_buf* buf;
    struct stat fd_stat;
    
    if (bsa_buf_pool == NULL){
        BSA_init_buf_pool();
        BSA_log("init buf\n");
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
    
    puts("return buf");
    buf->len = buf_size;
    
    if (bsa_buf_pool->buf_head == NULL){
        bsa_buf_pool->buf_head = buf;
    }
    else{
        bsa_buf_pool->buf_tail->next = buf;
    }
    bsa_buf_pool->buf_tail = buf;

    return buf;
}

int BSA_dump_buf(){
    struct BSA_buf* buf; 
    int out_fd;
    int count = 0;
    char path[256];

    if (access(BSA_dump_dir, F_OK) !=0 && (mkdir(BSA_dump_dir, 0700) != 0)){
        BSA_err("Can not create dump directory");
    }

    /*
     * dump previous inputed data as fuzzer's seed
     */
    if (bsa_buf_pool == NULL)
        return -1;

    buf = bsa_buf_pool->buf_head;
    if (buf != NULL){
        while(buf){
            sprintf(path, "%s/testcase_%d", BSA_dump_dir, count++);
            out_fd = open(path, O_CREAT|O_RDWR, 0600);    
            BSA_log("creating testcase: %s\n", path);
            if (out_fd == -1){
                BSA_err("Can not create testcase file")
            }
            write(out_fd, buf->data, buf->len);
            buf = buf->next;
            close(out_fd);
        }
        BSA_clear_buf(); 
        return 0;
    }
    else{
        return -1;
        /*
        int rand_fd;
        char buf[4096];
        printf("No testcase input\n");
        rand_fd = open("/dev/urandom", O_RDONLY);
        sprintf(path, "%s/no_testcase", BSA_dump_dir);
        out_fd = open(path, O_CREAT|O_RDWR, 0600);  
        if (!out_fd || !rand_fd){
            BSA_err("Cannot create random seed for AFL\n");
            return;
        }
        read(rand_fd, buf, 4096);
        write(out_fd, buf, 4096);
        close(rand_fd);
        close(out_fd);
        */
    }
}

void BSA_clear_buf(){
    
    struct BSA_buf* buf = bsa_buf_pool->buf_head;
    struct BSA_buf* tmp_buf;

    while(buf){
        tmp_buf = buf;
        buf = buf->next;
        free(tmp_buf->data);
        free(tmp_buf);
    }
    bsa_buf_pool->buf_head = NULL;
    bsa_buf_pool->buf_tail = NULL;
}

