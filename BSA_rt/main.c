#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>

#include "utils.h"
#include "config.h"
#include "storage.h"
#include "hook.h"


typedef uint32_t F_ID;

extern void _afl_maybe_log(uint32_t);
extern void BSA_init_buf_pool();
extern void BSA_set_dump_dir(const char*);
extern void BSA_clear_buf(int);
extern __thread char BSA_dump_dir[4096];
extern struct BSA_buf_pool* bsa_buf_pool;

extern u32 _afl_prev_loc; 

pthread_t BSA_request_thread;
int set_stdin = 0;
int BSA_fuzz_req = 0;
// Global variables
__thread u32 BSA_state = BSARun; // 0


int BSA_entry_value_shmid;
u8 *BSA_entry_value_map;


struct BSA_info bsa_info = { 
    .pid = 0,
    .master_pid = 0,
    .start_time = 0,
    .criu_fd = -1,
    .afl_handshake_fd = -1,
    .afl_sts_fd = -1,
    .afl_ctl_fd = -1,
    .afl_shm_id = -1,
    .afl_dir = NULL,
    .afl_input_fd = -1,
    .afl_input_fp = NULL,
    .possibility_denominator = 100,
    .sk_list = NULL,
    .file_list = NULL
};


void* BSA_request_handler(void* arg){
    char req_sk[1024];
    int req = 0, req_fd, comm_fd;
    struct sockaddr_un client_addr;
    socklen_t socklen = sizeof(client_addr);

    sprintf(req_sk, "/tmp/BSA_req_%d.sock", getpid());
    //BSA_log("Request_handler_init %s\n" ,req_sk);
    req_fd = BSA_bind_socket(req_sk);
    memset(&client_addr, 0, sizeof(client_addr));

    while(1){
                
        if( (comm_fd = accept(req_fd, (struct sockaddr_un*)&client_addr, &socklen)) == -1){
            BSA_log("Accept incoming connection failed!\n");
            _exit(1);
        }
        if ( (read(comm_fd, &req, 4) == 4) && (req == 1) ){
            BSA_log("Get connection\n");
            read(comm_fd, &req, 4);
            BSA_fuzz_req = req;
        }
        else if( req == 2 ){
            int val, pid, id;
            read(comm_fd, &pid, 4);
            read(comm_fd, &id, 4);
            read(comm_fd, &val, 4);
            if (val < BSA_FUZZ_THRESHOLD){
                *(u8*)(BSA_entry_value_map+id) = 0;
            }else{
                *(u8*)(BSA_entry_value_map+id) = 1;
            }
            BSA_log("[BSA_request_handler] id: 0x%x, val: %d\n", id, val);
        }
        printf("%d\n", req);
        close(comm_fd);
    }
}

__attribute__((constructor)) 
static void BSA_initial(){
    //srand(time(NULL));
    //bsa_info.master_pid = getpid();
    if (BSA_state == BSARun){
        BSA_init_buf_pool();
        pthread_create(&BSA_request_thread, NULL, BSA_request_handler, NULL);
        
        if (BSA_entry_value_shmid)
            shmdt(BSA_entry_value_map);

        BSA_entry_value_shmid = shmget(IPC_PRIVATE, sizeof(u8)*0x10000, IPC_CREAT|IPC_EXCL|0600);
        BSA_entry_value_map = (u8*)shmat(BSA_entry_value_shmid, NULL, 0);
        memset(BSA_entry_value_map, 1, sizeof(u8)*0x10000);

        pthread_atfork(NULL, NULL, BSA_initial);
    }
}

//void BSA_checkpoint(int id, int can_fuzz){
void BSA_checkpoint(int id, int is_entry){
    
    struct timeval now;
    int pid, ret;
    char *dump_path;
    
    _afl_prev_loc = (_afl_prev_loc>>1) ^ id;
    switch(BSA_state){
    
    case BSADebugging:
    case BSARun:
       
        if ( BSA_fuzz_req && is_entry && *(BSA_entry_value_map+_afl_prev_loc) ){
            if ( BSA_fuzz_req != syscall(__NR_gettid) ){
                return;
            }
            /* Set flags */
            BSA_state = BSAFuzz;

            /* Set dump_path */
            gettimeofday(&now, NULL);
            dump_path = BSA_dump_dir;
            sprintf(dump_path, "/tmp/fuzz_%ld.%ld", now.tv_sec, now.tv_usec);
            if (BSA_dump_buf() == -1 ){
                BSA_state = BSARun;
                return;
            }
            pid = fork();
            //ret = syscall(__NR_clone, CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, 0, &pid, 0, 0);  
            if (!pid){
                BSA_fuzz_req = 0;
                /* setup dump dir */   
                bsa_info.pid = getpid();
                // close all opening socket, and record it. 
                BSA_close_sockets();
                BSA_fuzz_forkserver_prep();
                
                /* Dump previous input */
                BSA_conn_IA(id); 
                
                /* setup afl relative socket */
                BSA_accept_channel(&bsa_info.afl_handshake_fd, "afl_handshake");
                BSA_afl_handshake();
                BSA_accept_channel(&bsa_info.afl_ctl_fd, "afl_ctl_fd");
                BSA_accept_channel(&bsa_info.afl_sts_fd, "afl_sts_fd");
                copy_shm_pages();
                //install_seccomp();
                _afl_maybe_log(id);
            }
            else if(pid > 0){
                BSA_fuzz_req = 0;
                BSA_state = BSARun;
                BSA_log("Yep\n");
            }
            else{
                BSA_log("Fork failed");
                exit(0);
            }
        }
        break;
    case BSAFuzz:
        _afl_maybe_log(id);
        break;

    case BSAStop:
        break;
    }
}

