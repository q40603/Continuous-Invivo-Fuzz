#!/bin/sh

target=objs/nginx

CC=/root/BSA_test/third_party/afl-2.52b/afl-clang-fast  CFLAGS=-g ./configure --with-openssl=$HOME/openssl-1.0.1e --with-http_ssl_module && make
