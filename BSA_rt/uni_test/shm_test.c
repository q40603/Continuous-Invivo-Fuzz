#include <stdlib.h>
#include <sys/mman.h>

int main(){
    void *addr = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0);
    void *addr2 = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

    pause();
}
