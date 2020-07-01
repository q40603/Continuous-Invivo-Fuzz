#include <stdlib.h>

int a = 0;

#define x(g) \
    if (a == 0){ \
        g \
    } 
int main(){
    x(write(1, "aaaa", 4);)
}
