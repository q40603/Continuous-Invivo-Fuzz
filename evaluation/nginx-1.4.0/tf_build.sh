#!/bin/sh

target=objs/nginx


CC=/root/BSA_test/third_party/afl-2.52b/afl-BSA-clang-fast CFLAGS="-mllvm -config=/root/nginx-1.4.0/entry.conf -mllvm -level=2 -pthread" ./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make
#CC=/root/BSA_test/third_party/afl-2.52b/afl-BSA-clang-fast CFLAGS="-mllvm -level=1 -pthread" ./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make

#CC=clang CFLAGS="-Xclang -load -Xclang /root/BSA_test/third_party/afl-2.52b/afl-BSA-llvm-pass.so -mllvm -config=/root/nginx-1.4.0/entry.conf -mllvm -level=2 /root/BSA_test/third_party/afl-2.52b/afl-BSA-llvm-rt.o -pthread" ./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make

#./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make
#CC=afl-clang-fast CFLAGS=-g ./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make
#CC=wllvm CFLAGS=-g ./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make
#cp $HOME/BSA_test/BSA_pass/libBSAPass.so ./

#extract-bc $target
#opt -load ./libBSAPass.so -BSA $target.bc -o ${target}_out.bc
#clang ${target}_out.bc -D_LOCAL_AFL_INSTRUMENTED -o nginx $HOME/BSA_test/BSA_rt/BSA.o -lpthread -lcrypt -lpcre /root/openssl-1.0.1e/.openssl/lib/libssl.a /root/openssl-1.0.1e/.openssl/lib/libcrypto.a -ldl -lz -lprotobuf-c -lgcc_s
