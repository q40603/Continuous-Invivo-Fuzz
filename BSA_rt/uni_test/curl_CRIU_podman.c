/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* <DESC>
 * Very simple HTTP GET
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>

size_t receive_data(void * buffer, size_t size, size_t nmemb, FILE* file){
  printf("receive_data\n");
  size_t r_size = fwrite(buffer, size, nmemb, file);
  fclose(file);
  return r_size;
}

int main(void){
    CURL *curl;
    CURLcode res;
    struct curl_slist *list = NULL;

    char path[] = "/tmp/redis_ck.tar.gz";
    FILE *tar_file = fopen(path, "wb");
    char buffer[13];
    FILE * f = fopen ("/proc/sys/kernel/hostname", "rb");

    if (f)
    {
      fgets(buffer, 13, f);
      fclose (f);
    }

    if (buffer)
    {
      printf("%s\n", buffer);
      // start to process your data / extract strings here...
    }

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, "/run/podman/podman.sock");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_URL, "http://d/v3.0.0/libpod/containers/invivo_redis/checkpoint?export=true&leaveRunning=true&tcpEstablished=true&printStats=true&fileLocks=true");
        //curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "export=true&leaveRunning=true&tcpEstablished=true&printStats=true&fileLocks=true");

        list = curl_slist_append(list, "Expect:");
        list = curl_slist_append(list, "Transfer-Encoding: chunked");
        list = curl_slist_append(list, "Content-Type: application/octet; charset=us-ascii");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, tar_file);


        

        /* use a GET to fetch this */
        // curl_easy_setopt(curl, CURLOPT_HTTPPOST, 1L);
        
        /* Perform the request */
        res = curl_easy_perform(curl);

        /* Perform the request, res will get the return code */
    
        /* Check for errors */
        if(res != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    
        /* always cleanup */
        curl_easy_cleanup(curl);        
    }
  return 0;
}