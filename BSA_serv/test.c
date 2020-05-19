#include <stdlib.h>

int main(){

    int fd = open("t", 0);
    char buf[0x100];
    
    read(fd, buf, 4);
    write(1, buf, 4);
    if (fork()){
        sprintf(buf, "/proc/self/fd/%d", fd);
        fd = open(buf, 0);
    }
    read(fd, buf, 4);
    write(1, buf, 4);

}
