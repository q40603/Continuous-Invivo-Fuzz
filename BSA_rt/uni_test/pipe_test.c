#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sched.h>

int main(){

    int pip[2];
    
    char str[5];
    str[4] = 0;
        
    unshare(CLONE_FILES);
    pipe(pip);

    printf("%d\n", getpid());
    
    int a = 5;
    int b = 0;
   
    int fd = open("./testdata", O_RDONLY);
    unshare(CLONE_FILES);

    if (!fork()){
    unshare(CLONE_FILES);
        /*
        int pip2[2];
        pip2[0] = open("/proc/self/fd/3", O_RDONLY);
        pip2[1] = open("/proc/self/fd/4", O_WRONLY);


        close(3);
        close(4);
*/
        int a = 5;
        int b = 0;
        
        write(4, &a, 4);
        sleep(2);
        read(fd, str, 4);
        read(3, &b, 4);
        printf("child %d\n", b);
        pause();
       
    }
    sleep(1);
    read(fd, str, 4);
    read(3, &b, 4);
    printf("master %d, str %s\n", b, str);
    
    pause();
}
