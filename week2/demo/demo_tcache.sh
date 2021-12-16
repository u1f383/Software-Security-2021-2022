#!/bin/bash

gdb ./demo_tcache

# p *(tcache_entry*) 0x5555555593f0
# p *(tcache_perthread_struct*) 0x555555559010