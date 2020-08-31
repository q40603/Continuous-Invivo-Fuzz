#!/bin/bash

mkdir install

#CC=/root/BSA_test/third_party/afl-2.52b/afl-BSA-clang-fast CFLAGS="-mllvm -config=/root/eval/httpd-2.4.39/entry.conf -g -pthread" ./configure --with-included-apr --prefix=$HOME/eval/httpd-2.4.39/install
#CC=/root/BSA_test/third_party/afl-2.52b/afl-BSA-clang-fast  CFLAGS="-g -pthread" ./configure --enable-http2 --with-nghttp2=./nghttp2-1.41.0/install --with-included-apr --prefix=$HOME/eval/httpd-2.4.25/install

FLAGS="/root/BSA_test/third_party/afl-2.52b/afl-BSA-llvm-rt.o -Xclang -load -Xclang /root/BSA_test/third_party/afl-2.52b/afl-BSA-llvm-pass.so -mllvm  -mllvm -level=1 -pthread"

CC=clang  CFLAGS=$FLAGS ./configure --enable-http2 --with-nghttp2=/root/eval/httpd-2.4.25/nghttp2-1.8.0/install --with-included-apr --prefix=$HOME/eval/httpd-2.4.25/install

#./configure --enable-http2 --with-nghttp2=/root/eval/httpd-2.4.25/nghttp2-1.8.0/install --with-included-apr --prefix=$HOME/eval/httpd-2.4.25/install
make -j4 && make install

#cp ~/BSA_test/BSA_pass/libBSAPass.so ./
#extract-bc ./install/bin/httpd

#opt -load ./libBSAPass.so -BSA -config ./entry.conf ./install/bin/httpd.bc -o httpd.bc

#./srclib/apr/libtool --silent --mode=link clang -o insted_httpd ./httpd.bc -export-dynamic server/libmain.la modules/core/libmod_so.la modules/http/libmod_http.la server/mpm/event/libevent.la os/unix/libos.la -lpcre ./srclib/apr-util/libaprutil-1.la -lexpat ./srclib/apr/libapr-1.la -lrt -lcrypt -lpthread -ldl ~/BSA_test/BSA_rt/BSA.o -lprotobuf-c

#./srclib/apr/libtool --silent --mode=install install insted_httpd $HOME/httpd-2.4.39/

