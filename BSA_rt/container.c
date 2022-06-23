#define _GNU_SOURCE

#include "container.h"
#include "config.h"


char container_id[20];
char mac_addr[20];

void set_container_id(){
    FILE * f = fopen ("/proc/sys/kernel/hostname", "rb");
    if (f)
    {
      fgets(container_id, 13, f);
      fclose (f);
    }
}


void set_mac_addr(){
    FILE * f = fopen ("/sys/class/net/eth0/address", "rb");
    if (f)
    {
      fgets(mac_addr, 20, f);
      fclose (f);
    }   
}

int mac_the_same(){
    char cur_mac_addr[20];
    int result;
    FILE * f = fopen ("/sys/class/net/eth0/address", "rb");
    if (f)
    {
        fgets(cur_mac_addr, 20, f);
        fclose (f);
        result = strcmp(cur_mac_addr, mac_addr);
        if(result == 0){
            //printf("%s, %s\n", mac_addr, cur_mac_addr);
            return 1;
        }
        else{
            return 0;
        }
    }
    return 0;
}

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

int container_checkpoint(int invivo_count){
  
    char ck_api[] = "http://d/v4.1.0/libpod/containers/";
    char ck_para[] = "/checkpoint?export=true&leaveRunning=true&tcpEstablished=true&printStats=true&fileLocks=true";
    

    char _container_id[20] = "1800d23d4f9f";
    char *url;
    asprintf(&url, "%s%s%s", ck_api, _container_id, ck_para);
    char *path;
    asprintf(&path, "/tmp/fuzz/%d.tar.gz", invivo_count);
    

    CURLcode ret;
    CURL *hnd;
    struct curl_slist *slist1;


    FILE *tar_file = fopen(path, "wb");

    if(!tar_file)
        return CK_FAIL;

    //printf("hihi\n");
    slist1 = NULL;
    slist1 = curl_slist_append(slist1, "Content-Type: application/tar");
    slist1 = curl_slist_append(slist1, "Transfer-Encoding:");
    slist1 = curl_slist_append(slist1, "Expect:");

    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(hnd, CURLOPT_URL, url);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.68.0");
    curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(hnd, CURLOPT_SSH_KNOWNHOSTS, "/root/.ssh/known_hosts");
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(hnd, CURLOPT_FTP_SKIP_PASV_IP, 1L);
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(hnd, CURLOPT_UNIX_SOCKET_PATH, "/run/podman/podman.sock");

    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, tar_file);
    /* Here is a list of options the curl code used that cannot get generated
        as source easily. You may select to either not use them or implement
        them yourself.

    CURLOPT_WRITEDATA set to a objectpointer
    CURLOPT_INTERLEAVEDATA set to a objectpointer
    CURLOPT_WRITEFUNCTION set to a functionpointer
    CURLOPT_READDATA set to a objectpointer
    CURLOPT_READFUNCTION set to a functionpointer
    CURLOPT_SEEKDATA set to a objectpointer
    CURLOPT_SEEKFUNCTION set to a functionpointer
    CURLOPT_ERRORBUFFER set to a objectpointer
    CURLOPT_STDERR set to a objectpointer
    CURLOPT_DEBUGFUNCTION set to a functionpointer
    CURLOPT_DEBUGDATA set to a objectpointer
    CURLOPT_HEADERFUNCTION set to a functionpointer
    CURLOPT_HEADERDATA set to a objectpointer

    */

    ret = curl_easy_perform(hnd);
    fclose(tar_file);

    curl_easy_cleanup(hnd);
    hnd = NULL;
    curl_slist_free_all(slist1);
    slist1 = NULL;


    free(url);
    free(path);

    if(ret != CURLE_OK)
        return CK_FAIL;


    return CK_SUCCESS;
}


