#include <stdlib.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/signal.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <stddef.h>
#include <errno.h>

void install_seccomp()
{
    
   struct sock_filter filter[] = {

       BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				(offsetof(struct seccomp_data, nr))),
       BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1), 
	   
       BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EWOULDBLOCK &  SECCOMP_RET_DATA)), 

       BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
   };

   struct sock_fprog prog = {
	   .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
	   .filter = filter,
   };
   if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0 ,0, 0, 0)){
       perror("NO_PRIVS");
       exit(1);
   }
   
   if (prctl(PR_SET_SECCOMP, 2, &prog)) {
	   perror("seccomp");
       exit(1);
   }
   
}
int main(){
    install_seccomp();
    char buf[4];
    read(0, buf, 4);
    perror("");
}
