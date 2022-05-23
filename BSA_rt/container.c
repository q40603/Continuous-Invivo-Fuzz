#define _GNU_SOURCE

#include "container.h"
#include "config.h"


char container_id[20];

void set_container_id(){
    FILE * f = fopen ("/sys/class/net/eth0/address", "rb");
    if (f)
    {
      fgets(container_id, 20, f);
      fclose (f);
    }
}

int container_match(){
    char cur_container_id[20];
    int result;
    FILE * f = fopen ("/sys/class/net/eth0/address", "rb");
    if (f)
    {
        fgets(cur_container_id, 20, f);
        fclose (f);
        result = strcmp(cur_container_id, container_id);
        if(result == 0){
            printf("%s, %s\n", container_id, cur_container_id);
            return 1;
        }
        else{
            return 0;
        }
    }
    return 0;
}


