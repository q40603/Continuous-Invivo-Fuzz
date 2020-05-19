#include "rpc.pb-c.h"
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>

#define MAX_MSG_SIZE 1024
#define MAX_MSG_SIZE 1024

char* BSA_criu_get_sock_path();
CriuResp* BSA_criu_recv(int socket_fd);
int BSA_criu_req(CriuReq *req);

