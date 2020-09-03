# In-Vivo Fuzzing Test Framework



### Compilation

- Complie runtime library
- Compile LLVM BSA Mode
- Use following flags

```
CC=afl-IV-clang-fast CFLAGS="-mllvm -config=/root/nginx-1.4.0/entry.conf -mllvm -level=2 -pthread
```

### Launch IA server
```
python3 IA_server.py
```

### Send Fuzzing Request
```
./req type pid tid bbid
```

