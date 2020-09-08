#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int main(){
    int eventfd = epoll_create(1);
    struct epoll_event event;
    event.events = EPOLLIN;
    epoll_ctl(eventfd, EPOLL_CTL_ADD, 0, &event);
    

    int pid =fork();

    if (!pid){
        
        //eventfd = open("/proc/self/fd/3", O_RDWR);

        while (epoll_wait(eventfd, &event, 10, 2000) <= 0){
            perror("GG");
        }


    }
    else{
        while (epoll_wait(eventfd, &event, 10, 2000) <= 0){
            printf("waiting...\n");
        }
    }
}
