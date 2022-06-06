#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <stdio.h>


int main(int argc, char** argv){
    struct sockaddr_un addr;
    int addr_len;
    int sockfd;
    int is_report = 0, pid, tid, bid, val, type = atoi(argv[1]);


    if (type == 1){
        is_report = 0;
        pid = atoi(argv[2]);
        // tid = atoi(argv[3]);
        // bid = atoi(argv[4]);
        
    }else if (type == 3){
        is_report = 1;
        pid = atoi(argv[2]);
        bid = atoi(argv[3]);
        val = atoi(argv[4]);
    }else{
        printf("No such req\n");
        exit(0);
    }

    sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    
    memset(&addr, 0, sizeof(struct sockaddr_un)); 
    addr.sun_family = AF_LOCAL;
    sprintf(addr.sun_path, "/tmp/BSA_req_%d.sock", pid);
    addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);
    if(connect(sockfd, (struct sockaddr*)&addr, addr_len) < 0){
       perror("Can't connect bsa remote file server");
    }

    if (is_report == 0){
        int quest[1];
        quest[0] = 1;
        // quest[1] = tid ^ (bid<<16) ;
        if (write(sockfd, quest, 4) != 4){
            perror("write failed");
        }
    }else{
        int report[4];
        report[0] = 2;
        report[1] = getpid();
        report[2] = bid;
        report[3] = val;

        write(sockfd, report, 16);
        pause();
    }
    
}
