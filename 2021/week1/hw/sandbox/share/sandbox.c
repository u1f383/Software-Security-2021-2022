#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

struct _Register {
    unsigned long rax;
    unsigned long rbx;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rdi;
    unsigned long rsi;
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
} regs;

#define SET_REGENV() do { \
    asm(".intel_syntax noprefix"); \
    asm("xor rax, rax"); \
    asm("xor rbx, rbx"); \
    asm("xor rcx, rcx"); \
    asm("xor rdx, rdx"); \
    asm("xor rdi, rdi"); \
    asm("xor rsi, rsi"); \
    asm("xor r8,  r8"); \
    asm("xor r9,  r9"); \
    asm("xor r10, r10"); \
    asm("xor r11, r11"); \
    asm("xor r12, r12"); \
    asm("xor r13, r13"); \
    asm("xor r14, r14"); \
    asm("xor r15, r15"); \
    asm(".att_syntax noprefix"); \
    } while (0)

#define UPDATE_REGS() do { \
    asm("mov %%rax, %0\n" : "=r"(regs.rax)); \
    asm("mov %%rbx, %0\n" : "=r"(regs.rbx)); \
    asm("mov %%rcx, %0\n" : "=r"(regs.rcx)); \
    asm("mov %%rdx, %0\n" : "=r"(regs.rdx)); \
    asm("mov %%rdi, %0\n" : "=r"(regs.rdi)); \
    asm("mov %%rsi, %0\n" : "=r"(regs.rsi)); \
    asm("mov %%r8, %0\n" : "=r"(regs.r8));   \
    asm("mov %%r9, %0\n" : "=r"(regs.r9));   \
    asm("mov %%r10, %0\n" : "=r"(regs.r10)); \
    asm("mov %%r11, %0\n" : "=r"(regs.r11)); \
    asm("mov %%r12, %0\n" : "=r"(regs.r12)); \
    asm("mov %%r13, %0\n" : "=r"(regs.r13)); \
    asm("mov %%r14, %0\n" : "=r"(regs.r14)); \
    asm("mov %%r15, %0\n" : "=r"(regs.r15)); \
    } while (0)

const char epilogue[] = "H\xc7\xc0<\x00\x00\x00\x0f\x05"; // sys_exit
const char syscall_pattern[] = "\x0f\x05";
const char mov_r8_prefix[] = "I\xb8";
const char call_r8[] = "A\xff\xd0";

const char *regs_str[] = {
    "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8",
    "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
const char *call_reg_patterns[] = {
    "\xff\xd0",
    "\xff\xd3",
    "\xff\xd1",
    "\xff\xd2",
    "\xff\xd7",
    "\xff\xd6",
    "A\xff\xd0",
    "A\xff\xd1",
    "A\xff\xd2",
    "A\xff\xd3",
    "A\xff\xd4",
    "A\xff\xd5",
    "A\xff\xd6",
    "A\xff\xd7",
};

#define REG_CNT (sizeof(regs_str) / sizeof(regs_str[0]))

void syscall_monitor()
{
    UPDATE_REGS();
    if (regs.rax == 60) {
        printf("[sys_exit] rdi: 0x%lx, rsi: 0x%lx, rdx: 0x%lx\n", regs.rdi, regs.rsi, regs.rdx);
        exit(regs.rdi);
    } else {
        write(1, "Disallow !!\n", 12);
    }
}

void call_reg_monitor()
{
    write(1, "Disallow !!\n", 12);
}

void jmp_func(char *sc, int *idx, unsigned long func)
{
    memcpy(sc + *idx, mov_r8_prefix, sizeof(mov_r8_prefix)-1);
    *idx += sizeof(mov_r8_prefix)-1;
    
    memcpy(sc + *idx, &func, 8);
    *idx += 8;

    memcpy(sc + *idx, call_r8, sizeof(call_r8)-1);
    *idx += sizeof(call_r8)-1;
}

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    
    char *new_code_buf, *stack;
    int nr, sc_idx, new_code_idx;
    char shellcode[0x280] = {0};
    char prologue[20];

    stack = (char *) mmap((void *) 0x30000, 0x8000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0) + 0x4000;
    new_code_buf = (char *) mmap((void *) 0x40000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    memcpy(prologue+0, "H\xbc", 2);
    memcpy(prologue+2, &stack, 8);
    memcpy(prologue+10, "H\xbd", 2);
    memcpy(prologue+12, &stack, 8);

    nr = read(0, shellcode, 0x200);
    sc_idx = new_code_idx = 0;

    // ****** instrumentation ******
    memcpy(new_code_buf, prologue, sizeof(prologue));
    new_code_idx += sizeof(prologue);

    while (sc_idx < nr) {
        // syscall
        if (!memcmp(shellcode+sc_idx, syscall_pattern, sizeof(syscall_pattern)-1)) {
            jmp_func(new_code_buf, &new_code_idx, (unsigned long) syscall_monitor);
            sc_idx += sizeof(syscall_pattern)-1;
            continue;
        }

        // call <reg>
        int i = 0;
        for (; i < REG_CNT; i++) {
            if (!memcmp(shellcode+sc_idx, call_reg_patterns[i], strlen(call_reg_patterns[i]))) {
                jmp_func(new_code_buf, &new_code_idx, (unsigned long) call_reg_monitor);
                sc_idx += strlen(call_reg_patterns[i]);
                break;
            }
        }
        if (i < REG_CNT)
            continue;

        // normal insn
        new_code_buf[new_code_idx++] = shellcode[sc_idx++];
    }

    memcpy(new_code_buf+new_code_idx, epilogue, sizeof(epilogue)-1);
    new_code_idx += sizeof(epilogue)-1;

    mprotect(new_code_buf, 0x1000, PROT_READ | PROT_EXEC);
    SET_REGENV();
    ( (void (*)(void)) (new_code_buf) )();

    return 0;
}
