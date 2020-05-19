#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define FILE_SERVER_WRITE_FD 196

int bind_socket(char* sock_path){
    int fd;
    struct sockaddr_un serv_addr;
    
    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sun_family = AF_LOCAL;
    sprintf(serv_addr.sun_path, "%s", sock_path);

    if(bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1){
        perror("Failed to bind socket\n");
    }

    //unlink(serv_addr.sun_path);
    if(listen(fd, 1) == -1){
        perror("Failed to listen socket\n");
    }
    return fd;
}

void setup_channel(int* channel){
    struct sockaddr_un client_addr;
    socklen_t socklen = sizeof(client_addr);
    
    memset(&client_addr, 0, sizeof(client_addr));
    int comm_fd;
    if( (comm_fd = accept(*channel, (struct sockaddr_un*)&client_addr, &socklen)) == -1){
        perror("Accept incoming connection failed!\n");
    }
    close(*channel);
    dup2(comm_fd, *channel);
    close(comm_fd);
}

int open_file(char* file_name){
    int fd;
    fd = open(file_name, O_RDONLY);
    if(fd < 0){
        perror("[BSA_socket_server] No such file");
        exit(1);
    }
    return fd;
}

int main(int argc, char** argv){
    int listen_fd, file_fd, ret;
    
    char* socket_name = NULL, *file_name = NULL;
    char buf[4096];

    if(argc < 2){
        perror("./BSA_file_socket_server filepath");
        exit(1);
    }

    asprintf(&file_name, "%s/.cur_input", argv[1]);
    asprintf(&socket_name, "%s/file.sock", argv[1]);
    
    if(access(socket_name, F_OK) == 0){
        remove(socket_name);
    }

    file_fd = open_file(file_name);

    listen_fd = bind_socket(socket_name);
    
    /* wake up fuzz target after setup fuzzer input socket */
    write(FILE_SERVER_WRITE_FD, &file_fd, 4);

    setup_channel(&listen_fd);
    while(read(file_fd, buf, 4096) > 0){
        write(listen_fd, buf, 4096);
    }
    close(file_fd);
    close(listen_fd);
}



