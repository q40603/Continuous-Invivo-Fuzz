#!/bin/sh



CC=/root/BSA_test/third_party/afl-2.52b/afl-BSA-clang-fast CFLAGS="-mllvm -config=/root/eval/redis-5.0-rc1/entry.conf -mllvm -level=2 -pthread" make

#./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make
#CC=afl-clang-fast CFLAGS=-g ./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make
#CC=wllvm CFLAGS=-g ./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make
#cp $HOME/BSA_test/BSA_pass/libBSAPass.so ./

#extract-bc $target
#opt -load ./libBSAPass.so -BSA $target.bc -o ${target}_out.bc
#clang ${target}_out.bc -D_LOCAL_AFL_INSTRUMENTED -o nginx $HOME/BSA_test/BSA_rt/BSA.o -lpthread -lcrypt -lpcre /root/openssl-1.0.1e/.openssl/lib/libssl.a /root/openssl-1.0.1e/.openssl/lib/libcrypto.a -ldl -lz -lprotobuf-c -lgcc_s
