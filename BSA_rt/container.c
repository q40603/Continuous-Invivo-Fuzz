#include "container.h"

__thread char container_id[13];

void set_container_id(){
    FILE * f = fopen ("/proc/sys/kernel/hostname", "rb");
    if (f)
    {
      fgets(container_id, 13, f);
      fclose (f);
    }
}

bool container_match(){
    char cur_container_id[13];
    int result;
    FILE * f = fopen ("/proc/sys/kernel/hostname", "rb");
    if (f)
    {
        fgets(cur_container_id, 13, f);
        fclose (f);
        result = strcmp(cur_container_id, container_id);
        if(result == 0){
            return true;
        }
        else{
            return false;
        }
    }
    return false;
}


