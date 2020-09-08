#!/bin/bash

mkdir mysql
mkdir data

FLAGS="/root/BSA_test/third_party/afl-2.52b/afl-BSA-llvm-rt.o -Xclang -load -Xclang /root/BSA_test/third_party/afl-2.52b/afl-BSA-llvm-pass.so -mllvm -config=/root/eval/mysql-server-mysql-5.6.35/config -mllvm -level=2 -pthread"

#CC=clang CXX=clang++ cmake -DCMAKE_INSTALL_PREFIX=./mysql -DMYSQL_DATADIR=./data -DDEFAULT_CHARSET=utf8  -DDEFAULT_COLLATION=utf8_general_ci -DWITH_EXTRA_CHARSETS:STRING=all -DWITH_DEBUG=0 -DWITH_SSL=yes -DWITH_READLINE=1 -DENABLED_LOCAL_INFILE=1 -DWITHOUT_PARTITION_STORAGE_ENGINE=0 .. && make && make install
CC=clang CXX=clang++ CFLAGS=$FLAGS CXXFLAGS=$FLAGS cmake -DCMAKE_INSTALL_PREFIX=./mysql -DMYSQL_DATADIR=./data -DDEFAULT_CHARSET=utf8  -DDEFAULT_COLLATION=utf8_general_ci -DWITH_EXTRA_CHARSETS:STRING=all -DWITH_DEBUG=0 -DWITH_SSL=yes -DWITH_READLINE=1 -DENABLED_LOCAL_INFILE=1 -DWITHOUT_PARTITION_STORAGE_ENGINE=0 .. && make -j4 && make install

./mysql/scripts/mysql_install_db --user=root --basedir=./mysql --datadir=./data
