#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "elf_exec.h"

#define EAX 0
#define ECX 1
#define EDX 2
#define EBX 3
#define ESP 4
#define EBP 5
#define ESI 6
#define EDI 7

#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7
#define R8  8
#define R9  9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15

/*
 *                -=== x86_64 instruction format ===-
 *
 *      [ Prefix | opcode | ModR/M | SIB   | Displacement | immediate ]
 *         1(opt)   1,2,3  1 ifreq   1ifreq     0,1,2,4      0,1,2,4
 *
 *
 *             ModR/M                           SIB
 *
 *       7   6 5      3 2   0         7     6 5     3 2    0
 *      +-----+--------+-----+       +-------+-------+------+
 *      | Mod | Req/Op | R/M |       | Scale | Index | Base |
 *      +-----+--------+-----+       +-------+-------+------+
 */

typedef struct {
    uint8_t *code;
    uint8_t *cursor;
    size_t len;
    size_t capacity;
} stream_t;

#define STREAM_INIT_CAP 256

stream_t *stream_new(size_t init_cap)
{
    assert(STREAM_INIT_CAP > 8);
    stream_t *s = malloc(sizeof(stream_t));
    s->code = calloc(1, STREAM_INIT_CAP);
    s->cursor = s->code;
    s->len = 0;
    s->capacity = STREAM_INIT_CAP;
}

void stream_destroy(stream_t *s)
{
    free(s->code);
    free(s);
}

// Make sure there is at least needed_cap free bytes in the stream
void stream_reserve(stream_t *s, size_t needed_cap)
{
    if(((int)s->capacity - (int)s->len) < (int)needed_cap) {
        s->code = realloc(s->code, s->capacity*2);
        s->cursor = s->code + s->len;
        s->capacity *= 2;
    }
}

void stream_push8(stream_t *s, uint8_t val)
{
    stream_reserve(s, 1);
    *s->cursor = val;
    s->cursor++;
    s->len++;
}

void stream_push16(stream_t *s, uint16_t val)
{
    stream_reserve(s, 2);
    *((uint16_t *) s->cursor) = val;
    s->cursor += 2;
    s->len += 2;
}

void stream_push32(stream_t *s, uint32_t val)
{
    stream_reserve(s, 4);
    *((uint32_t *) s->cursor) = val;
    s->cursor += 4;
    s->len += 4;
}

void stream_push64(stream_t *s, uint64_t val)
{
    stream_reserve(s, 8);
    *((uint64_t *) s->cursor) = val;
    s->cursor += 8;
    s->len += 8;
}

/////////////////////////////// Instructions parts ////////////////////////////////////////////
void push_rex(stream_t *s, uint8_t w, uint8_t  r, uint8_t x, uint8_t b) {
    stream_push8(s, 0x40 | (w<<3) | (r<<2) | (x<<1) | b);
}

/////////////////////////////// Instructions ////////////////////////////////////////////////
void push_add_rax_imm32(stream_t *s, uint32_t imm32) {
    push_rex(s, 1, 0, 0, 0);
    stream_push8(s, 0x05);
    stream_push32(s, imm32);
}

void push_mov_r64_imm64(stream_t *s, uint8_t reg, uint64_t imm64) {
    push_rex(s, 1, 0, 0, (reg & 0x08) >> 3);
    stream_push8(s, 0xb8 | (reg & 0x07));
    stream_push64(s, imm64);
}

void push_syscall(stream_t *s) {
    stream_push16(s, 0x050f);
}

typedef struct {
    
} instruction_t;

////////////////////////////////////////////////////////////////////////
int main() {
    stream_t *s = stream_new(8);
    
    // TODO
    // - Set text section offset
    // - Compute text section length
    // - From that compute data section offest
    
    uint8_t *data = "Hello, World!\n";
    size_t data_len = strlen(data)+1;
    
    uint64_t mem_offset = 0x400000;
    uint64_t data_offset = 0;
    uint64_t text_offset = 0x1000;
    
    // Write
    push_mov_r64_imm64(s, RAX, 1);  // write
    push_mov_r64_imm64(s, RDI, 1);  // stdout
    push_mov_r64_imm64(s, RSI, mem_offset + data_offset);  // const char *buf
    push_mov_r64_imm64(s, RDX, data_len);  // len
    push_syscall(s);
    
    // syscal exit(123)
    push_mov_r64_imm64(s, RAX, 60);
    push_mov_r64_imm64(s, RDI, 123);
    push_syscall(s);
    
    // Output ELF file
    elf_exec_t *e = elf_exec_new(s->code, s->len);
    elf_exec_add_data(e, data, data_len, data_offset, mem_offset);
    elf_exec_add_text(e, s->code, s->len, text_offset, mem_offset);
    elf_exec_dump(e, "out.bin", data_offset, mem_offset + text_offset);
    elf_exec_destroy(e);
    
    // Cleanup
    stream_destroy(s);
    return 0;
}
