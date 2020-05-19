#define _GNU_SOURCE
#include "config.h"
#include "criu_rpc.h"

char* BSA_criu_get_sock_path(){
    char* home = getenv("HOME");
    char* path;
    asprintf(&path, "%s/BSA_image/criu.sock", home);
    return path;
}

int BSA_get_image_fd(){
	char* home = getenv("HOME");
    char* cmd;
    char* path;
    int pid = getpid();
    int dir_fd;
    asprintf(&path, "%s/BSA_image/%d", home, pid);
    asprintf(&cmd, "mkdir -p %s/BSA_image/%d", home, pid);
    system(cmd);
    

    if ( (dir_fd = open(path, O_DIRECTORY)) < 0){
        BSA_err("Can not create criu dump dir");
    }

    
    free(cmd);
    free(path);
    return dir_fd;

}

CriuResp* BSA_criu_recv(int socket_fd)
{
	unsigned char buf[MAX_MSG_SIZE];
	int len;
	CriuResp *msg = 0;

	len = read(socket_fd, buf, MAX_MSG_SIZE);
	if (len == -1) {
		perror("Can't read response");
		return NULL;
	}

	msg = criu_resp__unpack(NULL, len, buf);
	if (!msg) {
		perror("Failed unpacking response");
		return NULL;
	}

	return msg;
}

// if success return fd else -1;
int BSA_criu_dump()
{   
    char* sock_path;
    int fd, ret;
    struct sockaddr_un addr;
	socklen_t addr_len;
    
    CriuReq req = CRIU_REQ__INIT;
    CriuResp* resp = NULL;

    req.opts->has_leave_running = true;
	req.opts->leave_running = true;
	req.opts->images_dir_fd = BSA_get_image_fd();
	req.opts->has_shell_job = true;
	req.opts->shell_job = true;
    req.opts->has_log_level = true;
	req.opts->has_tcp_established = true;
	req.opts->tcp_established = true;
    req.opts->log_level = 4;

    
    fd = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
	if (fd == -1) {
		perror("Can't create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
    
    sock_path = BSA_criu_get_sock_path();
	strcpy(addr.sun_path, sock_path);
    free(sock_path);

	addr_len = strlen(addr.sun_path) + sizeof(addr.sun_family);

	ret = connect(fd, (struct sockaddr *) &addr, addr_len);
	if (ret == -1) {
		perror("Cant connect to socket");
	    return -1;
    }

	unsigned char buf[MAX_MSG_SIZE];
	int len;

	len = criu_req__get_packed_size(&req);

	if (criu_req__pack(&req, buf) != len) {
		perror("Failed packing request");
		return -1;
	}

	if (write(fd, buf, len)  == -1) {
		perror("Can't send request");
		return -1;
	}
    
    resp = BSA_criu_recv(fd);
	if (resp->type != CRIU_REQ_TYPE__DUMP){
		perror("Unexpected response type");
	}
	if (resp->success && resp->dump->has_restored && resp->dump->restored){
		puts("Restored!");
	}

	return fd;
}
