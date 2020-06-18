#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include "criu_rpc.h"
#include "config.h"
#include "utils.h"
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <signal.h>

extern int BSA_state;
extern struct BSA_info bsa_info;
extern void BSA_setup_fuzzer_input_fd();

uint8_t* _afl_area_ptr = NULL;
uint32_t _afl_prev_loc = 0;
uint32_t _afl_setup_failure = 0;

uint8_t* BSA_blocked_map = NULL;
int BSA_blocked_shmid;
struct timeval tv1, tv2, tv3, tv4;

void BSA_alarm_handler(int sig){
    BSA_log("Time out le \n");
    BSA_blocked_map[_afl_prev_loc] = 1;  
    exit(0);
}

void _afl_maybe_log(uint32_t id){
    int shm_id, pid, status;
    struct itimerval it, old_it;
    
    // Move it to checkpoint entry 
    //_afl_prev_loc = (_afl_prev_loc>>1) ^ id;

    // check state value;
    if (_afl_area_ptr){
_afl_store:
        _afl_area_ptr[_afl_prev_loc]++;
        if ( BSA_blocked_map[_afl_prev_loc] ){
            gettimeofday(&tv4,NULL);
            unsigned long val = 1000000 * (tv4.tv_sec-tv1.tv_sec)+ (tv4.tv_usec-tv1.tv_usec); 
            BSA_log("time child %ld\n", val);

            exit(0);
        }
        return;
    }
    
    if ( !_afl_setup_failure ){
        shm_id = bsa_info.afl_shm_id;
        if( shm_id != -1 ){
            _afl_area_ptr = shmat(shm_id, NULL, 0);
            assert((BSA_blocked_shmid = shmget(IPC_PRIVATE, 0x10000, IPC_CREAT|IPC_EXCL|0600)) != -1);
            BSA_blocked_map = shmat(BSA_blocked_shmid, NULL, 0);
            signal(SIGCHLD, SIG_DFL);
            if (write(STS_CHANNEL_FD, &status, 4) == 4){
                while(1){
                    if (read(CTL_CHANNEL_FD, &status, 4) != 4){
                        exit(1);
                    }
                    gettimeofday(&tv2,NULL);
                    unsigned long val = 1000000 * (tv2.tv_sec-tv1.tv_sec)+ (tv2.tv_usec-tv1.tv_usec); 
                    BSA_log("time2 %ld\n", val);

                    pid = fork();
                    gettimeofday(&tv1,NULL);
                    if (pid < 0){
                        BSA_err("Fork fuzzing target failed\n");
                    }
                    else if (!pid){
                        sigset_t new, old;
                        signal(SIGALRM, BSA_alarm_handler);
                        BSA_setup_fuzzer_input_fd();
                        BSA_reopen_fd();
                        it.it_value.tv_usec = 0;
                        it.it_value.tv_sec = 1;
                        sigemptyset(&new);
                        sigaddset(&new, SIGALRM);
                        sigprocmask(SIG_UNBLOCK, &new, &old);
                        setitimer(ITIMER_REAL, &it, &old_it);
                        goto _afl_store;
                    }
                    else{
                        write(STS_CHANNEL_FD, &pid, 4);
                        waitpid(pid,&status,0);
                        gettimeofday(&tv3,NULL);
                        unsigned long val = 1000000 * (tv3.tv_sec-tv1.tv_sec)+ (tv3.tv_usec-tv1.tv_usec); 
                        BSA_log("time1 %ld\n", val);

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
