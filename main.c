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
void push_rex(stream_t *s, uint8_t w, uint8_t  r, uint8_t x, uint8_t b)
{
    stream_push8(s, 0x40 | (w<<3) | (r<<2) | (x<<1) | b);
}

/////////////////////////////// Instructions ////////////////////////////////////////////////
void push_add_rax_imm32(stream_t *s, uint32_t imm32)
{
    push_rex(s, 1, 0, 0, 0);
    stream_push8(s, 0x05);
    stream_push32(s, imm32);
}

void push_mov_r64_imm64(stream_t *s, uint8_t reg, uint64_t imm64)
{
    push_rex(s, 1, 0, 0, (reg & 0x08) >> 3);
    stream_push8(s, 0xb8 | (reg & 0x07));
    stream_push64(s, imm64);
}

void push_syscall(stream_t *s)
{
    stream_push16(s, 0x050f);
}

typedef struct {
    char names[100][255];
    uint64_t addrs[100];
    size_t count;
} symtable_t;

uint64_t symtable_get(symtable_t *s, const char *name)
{
    for(int i=0; i<=s->count; ++i) {
        if(strcmp(name, s->names[i]) == 0) return s->addrs[i];
    }
    
    return 0;
}

typedef struct {
    uint64_t offset;
    uint8_t *buffer;
    uint64_t len;
    uint64_t cap;
} segment_t;

uint64_t seg_alloc(segment_t *s, size_t len)
{
    // Resize buffer if can't fit len bytes in
    if(s->cap == 0) {
        s->cap = len;
        s->buffer = realloc(s->buffer, s->cap);
    } else if((s->cap - s->len)  < len) {
        s->cap *= 2;
        s->buffer = realloc(s->buffer, s->cap);
    }
    
    uint64_t new_ptr = s->len;
    s->len += len;
    
    return new_ptr;
}

void seg_copy(segment_t *seg, symtable_t *symtable, const char *name, void *buf, size_t len) {
    uint64_t offset = seg_alloc(seg, len);
    memcpy(seg->buffer + offset, buf, len);
    
    memcpy(symtable->names[1], name, strlen(name));
    symtable->addrs[1] = seg->offset + offset;
    symtable->count++;
}

typedef enum {
    OP_MOV_R64_IMM64,
    OP_SYSCALL
} opcode_t;

typedef struct {
    opcode_t opcode;
    uint64_t operand1;
    uint64_t operand2;
} instruction_t;

////////////////////////////////////////////////////////////////////////
int main()
{
    uint64_t mem_offset = 0x400000;
    uint64_t data_offset = 0;
    uint64_t text_offset = 0x1000;
    
    segment_t seg_data = {
        .offset = mem_offset + data_offset,
        .buffer = NULL,
        .len = 0,
        .cap = 0
    };
    
    symtable_t symtable = {0};
    
    // Populate data segment with symbol
    seg_copy(&seg_data, &symtable, "msg", "This is the poop!!!\n", 21);
    
    // Program
    instruction_t program[] = {
        // Write mmsg
        { .opcode = OP_MOV_R64_IMM64, .operand1 = RAX, .operand2 = 1 },
        { .opcode = OP_MOV_R64_IMM64, .operand1 = RDI, .operand2 = 1 },
        { .opcode = OP_MOV_R64_IMM64, .operand1 = RSI, .operand2 = symtable_get(&symtable, "msg") },
        { .opcode = OP_MOV_R64_IMM64, .operand1 = RDX, .operand2 = 21 },
        { .opcode = OP_SYSCALL, .operand1 = 0, .operand2 = 0 },
        
        // EXIT(123)
        { .opcode = OP_MOV_R64_IMM64, .operand1 = RAX, .operand2 = 60 },
        { .opcode = OP_MOV_R64_IMM64, .operand1 = RDI, .operand2 = 123 },
        { .opcode = OP_SYSCALL, .operand1 = 0, .operand2 = 0 },
    };
    
    // Encode instructions
    stream_t *s = stream_new(8);
    
    for(int i=0; i<sizeof(program)/sizeof(instruction_t); ++i) {
        switch(program[i].opcode) {
        case OP_MOV_R64_IMM64:
            push_mov_r64_imm64(s, program[i].operand1, program[i].operand2);
            break;
        case OP_SYSCALL:
            push_syscall(s);
            break;
        default:
            printf("Error: unknown instruction\n");
            exit(1);
        }
    }
    
    // Output ELF file
    elf_exec_t *e = elf_exec_new(s->code, s->len);
    elf_exec_add_data(e, seg_data.buffer, seg_data.len, data_offset, mem_offset);
    elf_exec_add_text(e, s->code, s->len, text_offset, mem_offset);
    elf_exec_dump(e, "out.bin", data_offset, mem_offset + text_offset);
    elf_exec_destroy(e);
    
    // Cleanup
    free(seg_data.buffer);
    stream_destroy(s);
    return 0;
}
