#!/bin/bash
python3 ld_change.py ld-2.32.so decrypt_safe_linking
gdb ./D -ex "set exec-wrapper env 'LD_PRELOAD=./libc-2.32.so'"
