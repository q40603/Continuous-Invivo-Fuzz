#!/usr/bin/python3
import socket
import subprocess
import struct
import time
import os

Host = '127.0.0.1'
Port = 8001

#null_fp = open('/dev/null', 'rw')
def fuzz_handshake(conn):
    req = conn.recv(41)
    print(req)
    tp = chr(req[0])
    pid = struct.unpack('<I', req[1:5])[0]
    ppid = struct.unpack('<I', req[5:9])[0]
    seed_dir_len = struct.unpack('<I', req[9:13])[0]
    entry_block = struct.unpack('<I', req[13:17])[0]
    shm_id = struct.unpack('<I', req[17:21])[0]
    threshold = struct.unpack('<I', req[21:25])[0]
    afl_input_location_shm_id = struct.unpack('<I', req[25:29])[0]
    invivo_count = struct.unpack('<I', req[29:33])[0]
    function_len = struct.unpack('<I', req[33:37])[0]
    program_len = struct.unpack('<I', req[37:41])[0]
    program_name = conn.recv(program_len)
    program_name = program_name.decode('utf-8')
    print('program name: ', program_name)
    function_name = conn.recv(function_len)
    function_name = function_name.decode('utf-8')
    print('function entry name:', function_name)
    seed_dir = conn.recv(seed_dir_len)
    print('seed_dir:', seed_dir)
    seed_dir = seed_dir.decode('utf-8')

    print('[IA] get pid %d , seed_dir: %s' % (pid,  seed_dir))
    # CMD_FUZZ
    if tp == '\x00':
        print('[IA] fuzzing go')
        # checkpoint containers

        # launch fuzzer
        output_dir = '%s_output' % seed_dir

        if len(os.listdir(seed_dir)) == 0:
            print('[-] Get request but there is no seed file')
            open(seed_dir + '/test', 'w').write("fuck")

        # payload = 'GET / HTTP/1.0\n'
        # payload += 'transfer-encoding: chunked\n'
        # payload += 'Content-Length: 1001\n\n'
        # payload += 'A' * 0x3000 + '\n'
        #open(seed_dir + '/test', 'w').write(payload)
        #subprocess.call('cp -f /root/eval/mysql-server-mysql-5.6.35/payload %s/test0' % seed_dir, shell=True)

        #else:
        cmd = 'INVIVO=1 AFL_FAST_CAL=1 /root/scalable-invivo/third_party/AFLplusplus/afl-fuzz -i %s -o %s -t 200000000+ -P %d -r %d -y %d -H %d -u %d -j %d -- %s/%s' % (seed_dir, output_dir, pid, ppid, afl_input_location_shm_id, shm_id, entry_block, invivo_count , program_name, function_name)
        print(cmd)
        
        #subprocess.call(cmd, shell=True)


    else:
        print('WTF???')

    conn.close()

if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((Host, Port))
    sock.listen(5)

    print('Server started!')
    print('Waiting for connection')

    while True:
        conn, addr = sock.accept()
        print('Connected by ', addr)

        fuzz_handshake(conn)
