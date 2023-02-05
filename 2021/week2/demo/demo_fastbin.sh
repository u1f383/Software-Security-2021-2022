#!/bin/bash

gdb ./demo_tcache

# p *(tcache_entry*) 0x5555555593f0
# p main_arena.fastbinsY