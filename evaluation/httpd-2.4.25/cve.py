from pwn import *

r = remote('localhost',80)

payload = 'GET / HTTP/1.1\r\nUser-Agent: curl/7.50.1\r\nAccept: */*\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\nContent-Length: 0\r\n\r\n\r\n'

print(payload)
r.send(payload)
r.interactive()
