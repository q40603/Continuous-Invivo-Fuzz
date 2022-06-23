#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
// #include <uninstd.h>
#include "utils.h"
#include "config.h"
#include "storage.h"
#include "hook.h"
#include "container.h"


typedef uint32_t F_ID;

extern void _afl_maybe_log();
extern void BSA_init_buf_pool();
extern void BSA_set_dump_dir(const char*);
extern void BSA_clear_buf(int);
extern void set_container_id();
extern void set_mac_addr();
extern int mac_the_same();
extern int container_checkpoint(int);
extern __thread char BSA_dump_dir[4096];
extern struct BSA_buf_pool* bsa_buf_pool;

extern __thread PREV_LOC_T __afl_prev_loc[NGRAM_SIZE_MAX];
extern u8* BSA_blocked_map;

pthread_t BSA_request_thread;
int set_stdin = 0;
int *BSA_fuzz_req = NULL;
// Global variables
__thread u32 BSA_state = BSARun; 
extern char mac_addr[20];
extern sem_t mutex; 

// int fun_cnt = 0;
int BSA_entry_value_shmid;
u8 *BSA_entry_value_map;

__thread int invivo_count = 0;
__thread char *function_entry_name;
__thread char *fuzz_function = NULL;




struct BSA_info bsa_info = { 
    .pid = 0,
    .master_pid = 0,
    .start_time = 0,
    .criu_fd = -1,
    .afl_handshake_fd = -1,
    .afl_sts_fd = -1,
    .afl_ctl_fd = -1,
    .afl_shm_id = -1,
    .afl_input_location_shm_id = -1,
    .afl_input_fd = -1,
    .afl_input_fp = NULL,
    .possibility_denominator = 100,
#ifdef _IV_DEBUG
    .debug_level = 1,
#else
    .debug_level = 0,
#endif
    .sk_list = NULL,
    .file_list = NULL
};

static int BSA_req_fd = -1;

void* BSA_request_handler(void* arg){
    int req = 0, comm_fd;
    int val, pid, id, fun_len;
    struct sockaddr_un client_addr;
    socklen_t socklen = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));

    while(1){
                
        if( (comm_fd = accept(BSA_req_fd, (struct sockaddr_un*)&client_addr, &socklen)) == -1){
            BSA_log("Accept incoming connection failed!\n");
            _exit(1);
        }
        if(read(comm_fd, &req, 4) == 4){
            *BSA_fuzz_req = req;
            BSA_log("Fuzz req = %d\n", req);
            switch(req){
                case AUTO_FUZZ:
                    // select entry prior to socket read
                    break;

                case FUNCTION_FUZZ:
                    if(fuzz_function){
                        free(fuzz_function);
                        fuzz_function = NULL;
                    }
                        
                    
                    read(comm_fd, &fun_len, 4);
                    fuzz_function = calloc(fun_len, 1);
                    read(comm_fd, &fuzz_function, fun_len);
                    // select certain function as entry
                    break;


                case REPORT_FUZZ:
                    // report fuzzing entry
                    
                    read(comm_fd, &pid, 4);
                    read(comm_fd, &id, 4);
                    read(comm_fd, &val, 4);
                    if (val < BSA_FUZZ_THRESHOLD){
                        *(u8*)(BSA_entry_value_map+id) = 0;
                    }else{
                        *(u8*)(BSA_entry_value_map+id) = 1;
                    }
                    BSA_log("[BSA_request_handler] id: 0x%x, val: %d\n", id, val);                
                    break;

                default:
                    break;    

            }
        }
        close(comm_fd);
        // if ( (read(comm_fd, &req, 4) == 4) && (req == 1) ){
        //     BSA_log("Get connection\n");
        //     *BSA_fuzz_req = req;
        //     // read(comm_fd, &req, 4);
        //     // BSA_fuzz_req = req;
        // }
        // else if(req == 2){
        //     *BSA_fuzz_req = req;
        // }
        // else if( req == 3 ){
        //     int val, pid, id;
        //     read(comm_fd, &pid, 4);
        //     read(comm_fd, &id, 4);
        //     read(comm_fd, &val, 4);
        //     if (val < BSA_FUZZ_THRESHOLD){
        //         *(u8*)(BSA_entry_value_map+id) = 0;
        //     }else{
        //         *(u8*)(BSA_entry_value_map+id) = 1;
        //     }
        //     BSA_log("[BSA_request_handler] id: 0x%x, val: %d\n", id, val);
        // }
        //printf("%d\n", req);
        // close(comm_fd);
    }
}



// void BSA_clean(void){
//     char req_sk[1024];
//     if(BSA_state == BSARun){
//         sprintf(req_sk, "/tmp/BSA_req_%d.sock", getpid());
//         BSA_unlink_socket(req_sk);
//         pthread_atfork(NULL, NULL, BSA_clean);
//     }

// }

void create_output_top_dir(){
    struct stat st = {0};
    if (stat("/tmp/fuzz", &st) == -1) {
        mkdir("/tmp/fuzz", 0700);
    }
}




__attribute__((constructor(INVIVO_PRIO)))
void BSA_initial(void){
    //srand(time(NULL));
    //bsa_info.master_pid = getpid();
    int req_fd, fuzz_req_shm_id=0;
    char req_sk[1024];

    //atexit(BSA_clean);
    
    if (BSA_state == BSARun){
        //sem_init(&mutex, 0, 1); 
        if(fuzz_req_shm_id)
            shmdt(BSA_fuzz_req);
        
        assert((fuzz_req_shm_id = shmget(IPC_PRIVATE, 0x10000, IPC_CREAT|IPC_EXCL|0777)) != -1);
        
        if((BSA_fuzz_req = (int *)shmat(fuzz_req_shm_id, NULL, 0)) == (void *)-1){
            perror("BSA_fuzz_req shmat failed");
            exit(0);        
        }
        set_mac_addr();
        set_container_id();
        create_output_top_dir();
        BSA_init_buf_pool();

        sprintf(req_sk, "/tmp/BSA_req_%d.sock", getpid());
        req_fd = BSA_bind_socket(req_sk);
        if (req_fd == -1)
            return;
        
        BSA_req_fd = req_fd;
        
        pthread_create(&BSA_request_thread, NULL, BSA_request_handler, NULL);
        if (BSA_entry_value_shmid)
            shmdt(BSA_entry_value_map);

        BSA_entry_value_shmid = shmget(IPC_PRIVATE, sizeof(u8)*0x10000, IPC_CREAT|IPC_EXCL|0777);
        BSA_entry_value_map = (u8*)shmat(BSA_entry_value_shmid, NULL, 0);



        memset(BSA_entry_value_map, 0, sizeof(u8)*0x10000);

        //pthread_atfork(NULL, NULL, BSA_initial);

    }
}



void pause_signal_handler(int signal)
{
        printf("Signal %d caught\n", signal);
}


int _afl_edge = 0;
void BSA_checkpoint_nofork(int id, int is_entry, char *function_name){
    
    struct timeval now;
    int pid;
    char *dump_path;
    // int req_bbid, req_tid;
    _afl_edge = (_afl_edge >> 1) ^ id;
    function_entry_name = function_name;
    switch(BSA_state){
    
    case BSADebugging:
    case BSARun:
        
        // req_bbid = BSA_fuzz_req >> 16;
        // req_tid = BSA_fuzz_req & 0xffff;
        //fun_cnt ++;
        // if ( (req_bbid == 0 && is_entry && *(BSA_entry_value_map+_afl_edge)) ){
        if ( (*BSA_fuzz_req == AUTO_FUZZ && *(BSA_entry_value_map+_afl_edge)) ){
        //|| (*BSA_fuzz_req == FUNCTION_FUZZ && fuzz_function!=NULL && !strcmp(fuzz_function , function_name))){

            /* Set flags */
            
            
            if(!container_checkpoint(invivo_count)){
                BSA_log("Container Chekcpoint fails\n");
                return;
            }

            BSA_state = BSAPrep;
            // struct sigaction act;

            // act.sa_handler =  pause_signal_handler;
            // sigaction(SIGCONT, &act, NULL);
            // pause();
            if(mac_the_same()){
                BSA_state = BSARun;
                return;
            }
            // if (-1 == ret){
            //     BSA_err("Process exited\n");
            // }
                

            /* Set dump_path */
            gettimeofday(&now, NULL);
            dump_path = BSA_dump_dir;
            sprintf(dump_path, "/tmp/fuzz/fuzz_%ld.%ld",  now.tv_sec, now.tv_usec);
            if (BSA_dump_buf() == -1 ){
                BSA_state = BSARun;
                return;
            }
            invivo_count ++;
            


            pid = getpid();
 
                
            *BSA_fuzz_req = -1;
            /* setup dump dir */   
            bsa_info.pid = pid;

                // close all opening socket, and record it. 
            BSA_sockets_handler_nofork();
            BSA_forkserver_prep();
                
            /* Dump previous input */
            BSA_conn_IA(_afl_edge, id); 
                
            /* setup afl relative socket */
            BSA_accept_channel(&bsa_info.afl_ctl_fd, "afl_ctl_fd");
            BSA_accept_channel(&bsa_info.afl_sts_fd, "afl_sts_fd");
            //copy_shm_pages();
            //install_seccomp();

            BSA_state = BSAFuzz;
            _afl_maybe_log(id);
            // else if(pid > 0){
            //     BSA_fuzz_req = -1;
            //     BSA_state = BSARun;
            //     BSA_log("Yep\n");
            // }
            // else{
            //     BSA_log("Fork failed");
            //     exit(0);
            // }
        }
        break;
    case BSAFuzz:
        if(BSA_blocked_map[__afl_prev_loc[0]]){
        //if(BSA_blocked_map[_afl_edge]){
            exit(0);
        }
        break;
    default:
        break;
    }
}

void BSA_checkpoint(int id, int is_entry, char *function_name){
    
    struct timeval now;
    int pid;
    char *dump_path;
    //int req_bbid, req_tid;
    _afl_edge = (_afl_edge >> 1) ^ id;
    //__afl_prev_loc[0] = (__afl_prev_loc[0]>>1) ^ id;
    //BSA_log("Yep %d %d\n", id, is_entry);
    switch(BSA_state){
    
    case BSADebugging:
    case BSARun:
        
        // req_bbid = BSA_fuzz_req >> 16;
        // req_tid = BSA_fuzz_req & 0xffff;
        //fun_cnt ++;
        //if ( (req_bbid == 0 && is_entry && *(BSA_entry_value_map+_afl_edge)) || (id == req_bbid && is_entry) ){
        if ( (*BSA_fuzz_req == 1 && *(BSA_entry_value_map+_afl_edge)) ){
            // if ( req_tid != syscall(__NR_gettid) ){
            //     return;
            // }
            /* Set flags */
            BSA_state = BSAPrep;

            /* Set dump_path */
            gettimeofday(&now, NULL);
            dump_path = BSA_dump_dir;
            sprintf(dump_path, "/tmp/fuzz/fuzz_%ld.%ld", now.tv_sec, now.tv_usec);
            if (BSA_dump_buf() == -1 ){
                BSA_state = BSARun;
                return;
            }
            pid = fork();
 
            if (!pid){
                
                *BSA_fuzz_req = -1;
                /* setup dump dir */   
                bsa_info.pid = getpid();

                // close all opening socket, and record it. 
                BSA_sockets_handler();
                BSA_forkserver_prep();
                
                /* Dump previous input */
                //BSA_conn_IA(__afl_prev_loc[0], id); 
                BSA_conn_IA(_afl_edge, id);
                
                /* setup afl relative socket */
                BSA_accept_channel(&bsa_info.afl_ctl_fd, "afl_ctl_fd");
                BSA_accept_channel(&bsa_info.afl_sts_fd, "afl_sts_fd");
                copy_shm_pages();
                //install_seccomp();

                BSA_state = BSAFuzz;
                _afl_maybe_log(id);
            }
            else if(pid > 0){
                *BSA_fuzz_req = -1;
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
        if(BSA_blocked_map[_afl_edge]){
            exit(0);
        }
        //BSA_log("bb = %d\n", id);
        //_afl_maybe_log(id);
        break;
    default:
        break;
    }
}

