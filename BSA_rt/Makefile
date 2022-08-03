SHELL:=/bin/bash

.PHONY: all

INCLUDE_DIR = ./include
#CFLAGS = -I./include -Wall -g -c -fPIC -pthread -lgcc_s -D_IV_DEBUG
#CFLAGS = -I./include -Wall -g -c -fPIC -pthread  -lcurl -lgcc_s -D_IV_DEBUG -DSECCOMP_DENY_epoll_wait 

CFLAGS = -I./include -Wall -g -c -fPIC -pthread -lgcc_s -D_IV_DEBUG -DSECCOMP_DENY_epoll_wait 
# CSHARED_FLAG = -I./include -fPIC -shared -lcurl -ldl
CSHARED_FLAG = -I./include -fPIC -shared -ldl
OBJ_DIR = ./objs/

CC = gcc
LD = ld 
LDFLAGS = -r
MAKE = make


all: 
	mkdir -p $(OBJ_DIR)
	$(MAKE) BSA
	$(MAKE) SEED_COLLECT

BSA: $(OBJ_DIR)main.o $(OBJ_DIR)storage.o $(OBJ_DIR)afl.o $(OBJ_DIR)utils.o $(OBJ_DIR)hook.o #$(OBJ_DIR)container.o 
	$(LD) -o $@.o $(LDFLAGS) $^



lib: $(OBJ_DIR)main.o $(OBJ_DIR)hook.o $(OBJ_DIR)storage.o $(OBJ_DIR)afl.o $(OBJ_DIR)utils.o #$(OBJ_DIR)container.o
	$(CC) -o libBSA.so $(CSHARED_FLAG) $^ 

SEED_COLLECT: $(OBJ_DIR)pre_load.o $(OBJ_DIR)main.o $(OBJ_DIR)storage.o $(OBJ_DIR)afl.o $(OBJ_DIR)utils.o #$(OBJ_DIR)container.o
	$(CC) -o $@.so $(CSHARED_FLAG) $^ 

$(OBJ_DIR)%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf BSA.o SEED_COLLECT.so $(OBJ_DIR)


.PHONY: clean
