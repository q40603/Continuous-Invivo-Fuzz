#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <stdio.h>

#define AUTO_FUZZ 1
#define FUNCTION_FUZZ 2
#define REPORT_FUZZ 3


int main(int argc, char** argv){
    struct sockaddr_un addr;
    int addr_len;
    int sockfd;
    int is_report = 0, tid, bid, val;
    int type = atoi(argv[1]), pid = atoi(argv[2]);
    char *buf;

    int function_quest[2], auto_quest[1], report[4];
    int fun_len;


    sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    
    memset(&addr, 0, sizeof(struct sockaddr_un)); 
    addr.sun_family = AF_LOCAL;
    sprintf(addr.sun_path, "/tmp/BSA_req_%d.sock", pid);
    addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);
    if(connect(sockfd, (struct sockaddr*)&addr, addr_len) < 0){
       perror("Can't connect bsa remote file server");
    }


    switch(type){
        case AUTO_FUZZ:
            auto_quest[0] = AUTO_FUZZ;
            if (write(sockfd, auto_quest, 4) != 4){
                perror("write failed");
            }            
            break;

        case FUNCTION_FUZZ:
            fun_len = strlen(argv[3]);
            
            function_quest[0] = FUNCTION_FUZZ;
            function_quest[1] = fun_len;
            write(sockfd, function_quest, 8);
            
            buf = calloc(fun_len,1);
            memcpy(buf, argv[3], fun_len);
            write(sockfd, buf, fun_len);
            break;

        case REPORT_FUZZ:
            report[0] = REPORT_FUZZ;
            report[1] = getpid();
            report[2] = bid;
            report[3] = val;
            write(sockfd, report, 16);
            break;

        default:
            printf("No such request\n");
            exit(0);
            break; 


    }

    return 0;
}
