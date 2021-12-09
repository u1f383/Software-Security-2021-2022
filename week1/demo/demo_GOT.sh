#!/bin/bash

gdb ./demo_GOT -ex 'set exec-wrapper env "LD_PRELOAD=/usr/src/glibc/glibc_dbg/libc.so"'