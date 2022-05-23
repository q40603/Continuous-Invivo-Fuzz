#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include "config.h"
#include "utils.h"
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>


#define PrintTime(x) \
    gettimeofday(&x,NULL); \
    unsigned long val = 1000000 * (x.tv_sec-tv1.tv_sec)+ (x.tv_usec-tv1.tv_usec); \
    BSA_log("time" #x "child %ld\n", val);



extern __thread int BSA_state;
extern struct BSA_info bsa_info;



u32 _afl_setup_failure = 0;

extern u8 * __afl_area_ptr;
extern __thread PREV_LOC_T __afl_prev_loc[NGRAM_SIZE_MAX];
extern PREV_LOC_T __afl_prev_caller[CTX_MAX_K];
extern u32        __afl_prev_ctx;

extern int _afl_edge;

u8* BSA_blocked_map = NULL;
int BSA_blocked_shmid;

static struct timeval tv1;//;, tv2, tv3, tv4;
static pthread_t input_thread;

void BSA_alarm_handler(int sig){
    //BSA_log("Time out le \n");
    //BSA_blocked_map[__afl_prev_loc[0]] = 1;  
    BSA_blocked_map[_afl_edge] = 1;
    exit(0);
}

void BSA_afl_input_thread(void* data){
    
    int listen_fd, file_fd, len;
    
    char* socket_name = NULL, *file_name = NULL;
    char buf[4096];
    char* fuzz_dir = bsa_info.afl_dir;

    asprintf(&file_name, "%s/default/.cur_input", fuzz_dir);
    asprintf(&socket_name, "%s/default/file.sock", fuzz_dir);
    
    while(1){
        
        if (read(FILE_SERVER_EVENT1_READ_FD, buf, 4) != 4){
            BSA_log("[%s][%d] input_thread wait failed\n", __FILE__, __LINE__);
        }
        if(access(socket_name, F_OK) == 0){
            assert(remove(socket_name) == 0);
        }

        listen_fd = BSA_bind_socket(socket_name);
        
        /* wake up fuzz target after setup fuzzer input socket */
        if (write(FILE_SERVER_EVENT2_WRITE_FD, &file_fd, 4) != 4){
            BSA_log("[%s][%d] sync failed\n", __FILE__, __LINE__);
        }

        BSA_accept_channel(&listen_fd, "afl_input_thread");
    

        file_fd = open(file_name, O_RDONLY);
        if (file_fd == -1){
            perror("open input file failed\n");
            exit(1);
        }

        while( (len = read(file_fd, buf, 4096)) > 0){
            //BSA_log("afl input read %d\n", len);
            if (write(listen_fd, buf, len) <= 0){
                break;
            }
            //BSA_log("-  afl write to interested socket %d with %s\n", len, buf);
        }
        close(file_fd);
        close(listen_fd);
    }
}


void _BSA_afl_initialize_forkserver(int shm_id){


    
    int pip[2];
    int pip2[2];
    
    
    if (( __afl_area_ptr = shmat(shm_id, NULL, 0) ) == (void *)-1){
        perror("shmat failed");
        exit(0);
    }
    assert((BSA_blocked_shmid = shmget(IPC_PRIVATE, 0x10000, IPC_CREAT|IPC_EXCL|0600)) != -1);
    BSA_blocked_map = shmat(BSA_blocked_shmid, NULL, 0);
    
    if(pipe(pip) < 0){  
        BSA_err("Pipe fail\n");   
    } 
    if(pipe(pip2) < 0){  
        BSA_err("Pipe fail\n");   
    }   


    if(dup2(pip[1], FILE_SERVER_EVENT1_WRITE_FD) == -1){
        BSA_err("dup2(pip[1], FILE_SERVER_EVENT1_WRITE_FD) 121 fails");   
        fflush(stderr); 
    }
        

    

    if(dup2(pip[0], FILE_SERVER_EVENT1_READ_FD) == -1){
        BSA_err("dup2(pip[0], FILE_SERVER_EVENT1_READ_FD) 124 fails");  
        fflush(stderr);
    }
          

    


    if(dup2(pip2[1], FILE_SERVER_EVENT2_WRITE_FD) == -1){
        BSA_err("dup2(pip2[1], FILE_SERVER_EVENT2_WRITE_FD) 133 fails"); 
        fflush(stderr);
    }
         

    if(dup2(pip2[0], FILE_SERVER_EVENT2_READ_FD) == -1){
        BSA_err("dup2(pip2[0], FILE_SERVER_EVENT2_READ_FD)  135 fails"); 
        fflush(stderr);
    }
        

    close(pip[1]); close(pip[0]);
    close(pip2[1]); close(pip2[0]);

    /* create input_thread */
    if ( pthread_create(&input_thread, NULL, (void*)BSA_afl_input_thread, NULL) != 0){
        perror("Thread_create failed\n");
    }

    /* false positive/negative may happend */
    //install_seccomp();
    signal(SIGCHLD, SIG_DFL);
}

void _BSA_afl_initialize_fuzz_target(){
    
    sigset_t new, old;
    char sock_name[4096];
    int addr_len;
    struct sockaddr_un addr;
    char buf[4];    
    struct itimerval it, old_it;
    memset(&it, 0, sizeof(struct itimerval));
    memset(&old_it, 0, sizeof(struct itimerval));
    /* wake up input thread */
    if(write(FILE_SERVER_EVENT1_WRITE_FD, buf, 4) !=4 ){
        BSA_log("[%s][%d] input_thread signal failed\n", __FILE__, __LINE__);
    }
    
    /* wait until socket setup */
	if(read(FILE_SERVER_EVENT2_READ_FD, buf, 4) != 4){
		BSA_err("Can not recv from file socket server\n");
	}
	sprintf(sock_name, "%s/default/file.sock", bsa_info.afl_dir);
	memset(&addr, 0, sizeof(addr));
	if ( (bsa_info.afl_input_fd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1){
		BSA_err("Can't create bsa_handshake socket\n");
	}
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, sock_name);
	addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);

	if(connect(bsa_info.afl_input_fd, (struct sockaddr*)&addr, addr_len) != 0){
	   BSA_err("Can't connect bsa remote file server");
	}
    
    /* close first, or will be bug */
	close(FILE_SERVER_EVENT1_WRITE_FD);
	close(FILE_SERVER_EVENT1_READ_FD);
    close(FILE_SERVER_EVENT2_WRITE_FD);
	close(FILE_SERVER_EVENT2_READ_FD);


	// create FILE* for this fd
	bsa_info.afl_input_fp = fdopen(bsa_info.afl_input_fd, "r");
	BSA_dup_target_fd();
    
    signal(SIGALRM, BSA_alarm_handler);
    BSA_reopen_fd();
    it.it_value.tv_usec = 0;
    it.it_value.tv_sec = 1;
    sigemptyset(&new);
    sigaddset(&new, SIGALRM);
    sigprocmask(SIG_UNBLOCK, &new, &old);
    if (setitimer(ITIMER_REAL, &it, &old_it) < 0){
        perror("Settimer");
    }
}



// int tiny_afl_maybe_log(int id){
//     if(BSA_state != BSAFuzz)
//         return -1;
    
//     __afl_area_ptr[_afl_edge ^ id]++;
//     _afl_edge = id >> 1;

//     return 1;
// }


void _afl_maybe_log(int id){

    // if(BSA_state != BSAFuzz)
    //     return;

    int shm_id, pid, status;
    
    // check state value;
    // if (__afl_area_ptr){
// _afl_store:
       
        //__afl_prev_loc = (__afl_prev_loc>>1) ^ id;
        // _afl_edge testing
        // __afl_area_ptr[__afl_prev_loc[0] ^ id]++;
        //_afl_edge = id >> 1;
        

        //_afl_area_ptr[__afl_prev_loc]++;
        // if ( BSA_blocked_map[__afl_prev_loc[0]] ){
        //     //PrintTime(tv3);
        //     exit(0);
        // }
        //return;
    // }

    // else{
    //     //BSA_log("_afl_area_ptr == NULL\n");
    // }
    
    if ( !_afl_setup_failure ){
        shm_id = bsa_info.afl_shm_id;
        //BSA_err("shm_id = %d, shm_id != -1 %d\n", shm_id, (shm_id != -1));
        //fflush(stderr);
        if( shm_id != -1 ){

            // printf("_BSA_afl_initialize_forkserver .....\n");
            // fflush(stdout);       
            _BSA_afl_initialize_forkserver(shm_id);
            // printf("success .....\n");
            // fflush(stdout);

            if (write(STS_CHANNEL_FD, &status, 4) == 4){
                //BSA_log("write STS_CHANNEL_FD success %d\n", status);
                while(1){
                    if (read(CTL_CHANNEL_FD, &status, 4) != 4){
                        perror("read CTL_CHANNEL_FD failed");
                        exit(1);
                    }
                    

                    //PrintTime(tv3);
                    gettimeofday(&tv1,NULL);
                    pid = fork();
                    
                    if (pid < 0){
                        BSA_err("Fork fuzzing target failed\n");
                    }
                    else if (!pid){
                        // BSA_state = BSAFuzz;
                        //BSA_log("_BSA_afl_initialize_fuzz_target\n");
                        _BSA_afl_initialize_fuzz_target();
                        //__afl_area_ptr[__afl_prev_loc[0] ^ id]++;
                        return;
                        //PrintTime(tv2);
                        // goto _afl_store;
                    }
                    else{
                        write(STS_CHANNEL_FD, &pid, 4);
                        waitpid(pid,&status,0);
                        
                        //PrintTime(tv4);

                        if (status != 0){
                            BSA_log("Failed status 0x%x\n", status);
                            if(WIFEXITED(status)) BSA_log("Exit status 0x%x\n", WEXITSTATUS(status));
                            if(WIFSIGNALED(status)) BSA_log("Termination signal 0x%x\n", WTERMSIG(status));
                        }
                        write(STS_CHANNEL_FD, &status, 4);
                    }
                }
            }
        }
        _afl_setup_failure++;
    }
    BSA_log("afl_setup_failure");
    _exit(1);
}
