#ifndef _CONTAINER_H
#define _CONTAINER_H

#include <string.h>
#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>

#define CK_SUCCESS 1
#define CK_FAIL 0

//function
void set_container_id();
void set_mac_addr();
int mac_the_same();
int container_checkpoint(int invivo_count);

#endif