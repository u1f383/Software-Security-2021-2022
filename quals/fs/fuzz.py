#!/usr/bin/python3

from pwn import *
import random

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./main')

def create_user(u, p):
    r.sendlineafter('> ', f"useradd {u} {p}")

def delete_user(u, p):
    r.sendlineafter('> ', f"userdel {u} {p}")

def login(u, p):
    r.sendlineafter('> ', f"login {u} {p}")

def create_normfile(fn):
    r.sendlineafter('> ', f"create normfile {fn}")

def create_dir(fn):
    r.sendlineafter('> ', f"create dir {fn}")

def delete_file(fn):
    r.sendlineafter('> ', f"rm {fn}")

def enc_file(fn, key):
    r.sendlineafter('> ', f"enc {fn} {key}")

def dec_file(fn, key):
    r.sendlineafter('> ', f"dec {fn} {key}")

def enter_dir(fn):
    r.sendlineafter('> ', f"cd {fn}")

def info(fn):
    r.sendlineafter('> ', f"info {fn}")

def read_file(fn):
    r.sendlineafter('> ', f"read {fn}")

def write_file(fn):
    r.sendlineafter('> ', f"write {fn}")
    r.sendline('A' * random.randint(1, 0x100))

def set_prot_file(fn, prot):
    r.sendlineafter('> ', f"set {fn} {prot}")

def unset_prot_file(fn, prot):
    r.sendlineafter('> ', f"unset {fn} {prot}")

def slss_file(fn):
    r.sendlineafter('> ', f"slss {fn}")

def slsd_file(fn):
    r.sendlineafter('> ', f"slsd {fn}")

def hlss_file(fn):
    r.sendlineafter('> ', f"hlss {fn}")

def hlsd_file(fn):
    r.sendlineafter('> ', f"hlsd {fn}")

fn_list = [ chr(i) for i in range(256) ] + [".."]
key_list = [ chr(i)*16 for i in range(256) ]
uname_list = [ chr(i)*8 for i in range(256) ]
pass_list = [ chr(i)*8 for i in range(256) ]

epoch = 0
while True:
    opt = random.randint(0, 18)
    u = uname_list[ random.randint(0, 255) ]
    p = pass_list[ random.randint(0, 255) ]
    fn = fn_list[ random.randint(0, 256) ]
    key = key_list[ random.randint(0, 255) ]

    if opt == 0:
        create_user(u, p)
    elif opt == 1:
        delete_user(u, p)
    elif opt == 2:
        login(u, p)
    elif opt == 3:
        create_normfile(fn)
    elif opt == 4:
        create_dir(fn)
    elif opt == 5:
        enc_file(fn, key)
    elif opt == 6:
        dec_file(fn, key)
    elif opt == 7:
        read_file(fn)
    elif opt == 8:
        write_file(fn)
    elif opt == 9:
        set_prot_file(fn, "read,write")
    elif opt == 10:
        unset_prot_file(fn, "read,write")
    elif opt == 11:
        slss_file(fn)
    elif opt == 12:
        slsd_file(fn)
    elif opt == 13:
        hlss_file(fn)
    elif opt == 14:
        hlsd_file(fn)
    elif opt == 15:
        enter_dir(fn)
    elif opt == 16:
        info(fn)
    elif opt == 17:
        r.sendlineafter('> ', 'ls')
    else:
        cnt = random.randint(1, 0x10)
        r.sendlineafter('> ', 'A'*cnt)

    epoch += 1
    if epoch % 1000 == 0:
        print("test...", epoch)

r.interactive()
