#!/bin/sh

target=objs/nginx

./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make

cp $HOME/BSA_test/BSA_pass/libBSAPass.so ./
cp $HOME/BSA_test/BSA_rt/BSA.o ./

extract-bc $target
opt -load ./libBSAPass.so -BSA -log -config ./entry.conf $target.bc -o ${target}_out.bc
$HOME/BSA_test/third_party/afl-2.52b/afl-clang ${target}_out.bc ./BSA.o -pthread -lrt -lz -lpcre -lcrypt -lcrypto -ldl -o nginx
