#!/bin/bash

gdb ./demo_canary -ex 'set exec-wrapper env "LD_PRELOAD=/usr/src/glibc/glibc_dbg/libc.so"'

# pwndbg> tls
# pwndbg> canary
# pwndbg> search -8 <canary>