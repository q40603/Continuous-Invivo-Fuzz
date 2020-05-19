#include "utils.h"
#include "config.h"
#include "storage.h"

extern struct BSA_info bsa_info;
extern struct BSA_buf_pool* bsa_buf_pool;
extern __thread  char BSA_dump_dir[4096];
extern bool set_stdin;

pthread_t input_thread;

void copy_shm_pages(){
    char path[1024];
    char maps[4096];
    char range[0x20];
    char *perm_str;
    int perm = PROT_NONE;
    u8* copy;

    u64 base, tmp, size;
    sprintf(path, "/proc/%d/maps", bsa_info.pid);
    FILE* fp = fopen(path, "r");
    while(fgets(maps, 4096, fp) ){
        perm = PROT_NONE;
        sscanf(strtok(maps, " \n"), "%s", range );
        perm_str = strtok(NULL, " ");

        if (strchr(perm_str, 'r') != NULL) perm |= PROT_READ;
        if (strchr(perm_str, 'w') != NULL) perm |= PROT_WRITE;
        if (strchr(perm_str, 'x') != NULL) perm |= PROT_EXEC;
        
        if (strchr(perm_str, 's') != NULL){
            for (int i=0;i<4;i++) strtok(NULL, " ");
            sscanf(range, "%lx-%lx", &base, &tmp );
            size = tmp-base;
            copy = malloc(size);
            memcpy(copy, (void*)base, size);
            munmap((void*)base, size);
            mmap((void*)base, size, perm, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
            memcpy((void*)base, copy, size);
            free(copy);
        }
            
    }
    fclose(fp);
}



void BSA_close_sockets(){
	struct dirent* direntp;
    struct stat st;
    DIR* dirp;
    int fd;
    int val;
    socklen_t val_length = sizeof(int);

    if ((dirp = opendir("/proc/self/fd")) == NULL){
        return;
    }
    
    while((direntp=readdir(dirp)) != NULL) {
        if (strcmp(direntp->d_name, ".") == 0 || strcmp(direntp->d_name, "..") == 0)
            continue;
        fd = atoi(direntp->d_name);
        fstat(fd, &st);
        
        // How about listening socket ???
        BSA_log("checking fd %d ...", fd);
        if (S_ISSOCK(st.st_mode)){
            BSA_log(" is socket!\n");
            getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &val, &val_length);
            if (val){
                BSA_log("close listening fd: %d\n", fd);
                close(fd);
            }
            else{
    		    BSA_update_fd_list(&bsa_info.sk_list, fd, st.st_mode);
            }
        }
        else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode) ){
            /* Not deal with this type fd */
            BSA_log(" is device!\n");
        }
		else if (S_ISREG(st.st_mode)){
            /* Copy file descriptor*/
            BSA_update_fd_list(&bsa_info.file_list, fd, st.st_mode);
            BSA_log(" is normal!\n");
        }else {
            BSA_update_fd_list(&bsa_info.file_list, fd, st.st_mode);
            BSA_log(" reopen extract fd\n");
        }
    }
    closedir(dirp);
}

void BSA_update_fd_list(struct FD_list** fd_list, int fd, mode_t mode){
    
    struct FD_node* cli_node = calloc(1, sizeof(struct FD_node));
    if (*fd_list == NULL){
        *fd_list = malloc(sizeof(struct FD_list));
        (*fd_list)->head = (*fd_list)->tail = cli_node;
    }
    else{
        (*fd_list)->tail->next = cli_node;
        (*fd_list)->tail = cli_node;
    }

    cli_node->fd = fd;
    cli_node->st_mode = mode;
    return;
}

void BSA_clear_sk_list(){
    struct FD_list* sk_list = bsa_info.sk_list;
    struct FD_node* sk_node, *tmp;

    if(!sk_list){
        return;
    }
    sk_node = sk_list->head;
    
    while(sk_node){
        tmp = sk_node;
        sk_node = sk_node->next;
        free(tmp);
    }
    
    free(bsa_info.sk_list);
    bsa_info.sk_list = NULL;
}


/*
 * bind AF_local socket by socket name
 */
int BSA_bind_socket(const char* name){
    int fd;
    struct sockaddr_un serv_addr;
    
    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sun_family = AF_LOCAL;
    sprintf(serv_addr.sun_path, "%s", name);

    if(bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1){
        BSA_log("%s", name);
        BSA_err("Failed to bind socket");
    }

    if(listen(fd, 1) == -1){
        BSA_err("Failed to listen socket\n");
    }
    return fd;
}

/*
 * Send pid, fuzz_seed_path, to IA
 * And ask IA to launch AFL-fuzz
 */
void BSA_conn_IA(int id){
    char* dump_path;
    struct sockaddr_in srv;
    char* buf, *out_dir;
    int ia_fd, path_len, buf_sz, entry_id = id, threshold = BSA_FUZZ_THRESHOLD ;
    
    dump_path = BSA_dump_dir; 

    if ( (ia_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        BSA_err("Failed to open IA socket\n");
    }

    memset(&srv, 0, sizeof(srv));

    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = inet_addr(BSA_srv_addr);
    srv.sin_port = htons(BSA_srv_port);

    if (connect(ia_fd, (struct sockaddr*)&srv, sizeof(srv)) == -1){
        BSA_err("Failed to connet to IA");
    }
     
    asprintf(&out_dir, "%s_output", dump_path);
    //printf("%s QQQQQQQQQQQQ", out_dir);
    mkdir(out_dir, 0700);
    free(out_dir);

    path_len = strlen(dump_path);
    buf_sz = 25 + path_len;
    
    buf = calloc(buf_sz ,1);
    
    bsa_info.master_pid = getppid();
    bsa_info.afl_shm_id = shmget(IPC_PRIVATE, 0x10000, IPC_CREAT|IPC_EXCL|0600);

    memcpy(buf+1, &(bsa_info.pid), 4);
    memcpy(buf+5, &(bsa_info.master_pid), 4);
    memcpy(buf+9, &path_len, 4);
    memcpy(buf+13, &entry_id, 4);
    memcpy(buf+17, &(bsa_info.afl_shm_id), 4);
    memcpy(buf+21, &threshold, 4);
    memcpy(buf+25, dump_path, path_len);

    write(ia_fd, buf, buf_sz);

    free(buf);
}

/*
 * Setup AFL channels and some system resources 
 */
void BSA_fuzz_forkserver_prep(){
    
    struct rlimit r;
    char file_path[256];
    int tmp_fd;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */
    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < BSA_SHADOW_FD ) {

      r.rlim_cur = BSA_SHADOW_FD;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }
    
    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    // setrlimit(RLIMIT_CORE, &r); /* Ignore errors */
    
    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    setsid();
    
    // for getting shmID
    sprintf(file_path, "/tmp/BSA_handshake_%d.sock", bsa_info.pid);
    tmp_fd = BSA_bind_socket(file_path);
    dup2(tmp_fd, HANDSHAKE_CHANNEL_FD);
    bsa_info.afl_handshake_fd = HANDSHAKE_CHANNEL_FD;
    close(tmp_fd);

    // for ctl channel
    sprintf(file_path, "/tmp/BSA_ctl_%d.sock", bsa_info.pid);
    tmp_fd = BSA_bind_socket(file_path);
    dup2(tmp_fd, CTL_CHANNEL_FD);
    bsa_info.afl_ctl_fd = CTL_CHANNEL_FD;
    close(tmp_fd);

    // for sts channel
    sprintf(file_path, "/tmp/BSA_sts_%d.sock", bsa_info.pid);
    tmp_fd = BSA_bind_socket(file_path);
    dup2(tmp_fd, STS_CHANNEL_FD);
    bsa_info.afl_sts_fd = STS_CHANNEL_FD;
    close(tmp_fd);
    
}

/* Get AFL-Fuzz Shared Memory ID and fuzzer input source */
void BSA_afl_handshake(){
    char buf[2048];
    
    BSA_log("AFL handshaking...\n");
    read(bsa_info.afl_handshake_fd, buf, sizeof(buf));
    
    /* check magic bytes */
    if (buf[0] == 'B' && buf[1] == 'S' && buf[2] == 'A'){
        char* tmp_str;
        tmp_str = strtok(buf, " ");
        
        // fuzzer dir
        tmp_str = strtok(NULL, " ");
        asprintf(&bsa_info.afl_dir, "%s", tmp_str);
        BSA_log("fuzzer dir: %s\n", bsa_info.afl_dir);
        
        tmp_str = strtok(NULL, " ");
        bsa_info.afl_shm_id = atoi(tmp_str);
        printf("Get shm_id: %d\n", bsa_info.afl_shm_id);
        close(bsa_info.afl_handshake_fd);
    }
    else{
        BSA_err("Error handshake value!\n")
    }

}

/*
 * Accept socket connection from AFL-fuzz
 */
void BSA_accept_channel(int* channel, const char* desc){
    struct sockaddr_un client_addr;
    socklen_t socklen = sizeof(client_addr);
    
    memset(&client_addr, 0, sizeof(client_addr));
    int comm_fd;
    if( (comm_fd = accept(*channel, (struct sockaddr_un*)&client_addr, &socklen)) == -1){
        BSA_log("[BSA setup channel][%s] Accept incoming connection failed!\n", desc);
        perror("");
        exit(1);
    }
    dup2(comm_fd, *channel);
    close(comm_fd);
}

/* Replace insterested fd to afl-fuzz fd */
void BSA_dup_target_fd(){
    
	//int dev_null_fd;
    if(set_stdin){
        dup2(bsa_info.afl_input_fd, 0);
    }
    /*
    dev_null_fd = open("/dev/null", O_RDWR);
    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);
*/
    if (bsa_info.sk_list == NULL){
        return;
    }
    struct FD_node *node = bsa_info.sk_list->head;
    while (node != NULL){
        dup2(bsa_info.afl_input_fd, node->fd);
        node = node->next;
    }
}

void BSA_reopen_fd(){
    int reopened_fd, pos, flag, fd;
    char buf[0x100];
    
    if (bsa_info.file_list == NULL){
        return;
    }
    struct FD_node *node = bsa_info.file_list->head;
    while (node != NULL){

        fd = node->fd;
        pos = lseek(fd, 0, SEEK_CUR);
        flag = fcntl(fd, F_GETFL, 0);
        sprintf(buf, "/proc/self/fd/%d", fd);
        reopened_fd = open(buf, flag);
        lseek(reopened_fd, pos, SEEK_SET);
        close(fd);
        dup2(reopened_fd, fd);
        close(reopened_fd);

        node = node->next;
    }
    
}

void BSA_afl_input_thread(void* data){
    
    int listen_fd, file_fd, len;
    
    char* socket_name = NULL, *file_name = NULL;
    char buf[4096];
    char* fuzz_dir = bsa_info.afl_dir;

    asprintf(&file_name, "%s/.cur_input", fuzz_dir);
    asprintf(&socket_name, "%s/file.sock", fuzz_dir);
    
    if(access(socket_name, F_OK) == 0){
        remove(socket_name);
    }

    file_fd = open(file_name, O_RDONLY);
    if (file_fd == -1){
        perror("open input file failed\n");
        exit(1);
    }
    listen_fd = BSA_bind_socket(socket_name);
    
    /* wake up fuzz target after setup fuzzer input socket */
    if (write(FILE_SERVER_WRITE_FD, &file_fd, 4) != 4){
        BSA_log("[%s][%d] sync failed", __FILE__, __LINE__);
    }
    close(FILE_SERVER_WRITE_FD);

    BSA_accept_channel(&listen_fd, "afl_input_thread");
    while( (len = read(file_fd, buf, 4096)) > 0){
        if (write(listen_fd, buf, len) <= 0){
            //BSA_log("AFL_input_thread write down\n");
            break;
        }
    }
    //close(file_fd);
    close(listen_fd);
    pause();
}


/* setup fuzzer input socker server */
void BSA_setup_fuzzer_input_fd(){
    char sock_name[4096];
    int addr_len;
    struct sockaddr_un addr;
    int pip[2];    
    char buf[4];    
    if(pipe(pip) < 0){  
        BSA_err("Pipe fail\n");   
    }    
    dup2(pip[1], FILE_SERVER_WRITE_FD);    
    dup2(pip[0], FILE_SERVER_READ_FD); 

    if ( pthread_create(&input_thread, NULL, (void*)BSA_afl_input_thread, NULL) != 0){
        perror("Thread_create failed\n");
    }
    
	if(read(FILE_SERVER_READ_FD, buf, 4) != 4){
		BSA_err("Can not recv from file socket server\n");
	}
	sprintf(sock_name, "%s/file.sock", bsa_info.afl_dir);
	memset(&addr, 0, sizeof(addr));
	if ( (bsa_info.afl_input_fd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1){
		BSA_err("Can't create bsa_handshake socket\n");
	}
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, sock_name);
	addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);
	if(connect(bsa_info.afl_input_fd, (struct sockaddr*)&addr, addr_len) < 0){
	   BSA_err("Can't connect bsa remote file server");
	}
    
    /* close first, or will be bug */
    close(pip[1]);
	close(pip[0]);
	close(FILE_SERVER_WRITE_FD);
	close(FILE_SERVER_READ_FD);

	// create FILE* for this fd
	bsa_info.afl_input_fp = fdopen(bsa_info.afl_input_fd, "r");
	BSA_dup_target_fd();
	
}

void install_seccomp()
{
    
   struct sock_filter filter[] = {

       BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				(offsetof(struct seccomp_data, nr))),

	   BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tgkill, 0, 1),
	   BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (SECCOMP_RET_DATA)),
	   
       BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
   };

   struct sock_fprog prog = {
	   .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
	   .filter = filter,
   };
   if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0 ,0, 0, 0)){
       perror("NO_PRIVS");
       exit(1);
   }
   
   if (prctl(PR_SET_SECCOMP, 2, &prog)) {
	   perror("seccomp");
       exit(1);
   }
   
}

