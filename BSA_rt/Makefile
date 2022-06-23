SHELL:=/bin/bash

.PHONY: all

INCLUDE_DIR = ./include
#CFLAGS = -I./include -Wall -g -c -fPIC -pthread -lgcc_s -D_IV_DEBUG
CFLAGS = -I./include -Wall -g -c -fPIC -pthread  -lcurl -lgcc_s -D_IV_DEBUG -DSECCOMP_DENY_epoll_wait 
CSHARED_FLAG = -I./include -fPIC -shared -lcurl
OBJ_DIR = ./objs/

CC = gcc
LD = ld 
LDFLAGS = -r
MAKE = make


all: 
	mkdir -p $(OBJ_DIR)
	$(MAKE) BSA

BSA: $(OBJ_DIR)main.o $(OBJ_DIR)hook.o $(OBJ_DIR)storage.o $(OBJ_DIR)afl.o $(OBJ_DIR)utils.o $(OBJ_DIR)container.o
	$(LD) -o $@.o $(LDFLAGS) $^


lib: $(OBJ_DIR)main.o $(OBJ_DIR)hook.o $(OBJ_DIR)storage.o $(OBJ_DIR)afl.o $(OBJ_DIR)utils.o $(OBJ_DIR)container.o
#criu.o 
	$(CC) -o libBSA.so $(CSHARED_FLAG) $^ 
	sudo cp -f ./libBSA.so /usr/lib/
	sudo cp -f $(INCLUDE_DIR)/* /usr/include/BSA/


$(OBJ_DIR)%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf BSA.o libBSA.so $(OBJ_DIR)


.PHONY: clean
