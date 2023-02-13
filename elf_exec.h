#ifndef ELF_EXEC_H
#define ELF_EXEC_H

#include <stdint.h>
#include <elf.h>

typedef struct {
    uint8_t *code;
    size_t code_len;
    uint8_t *file_buffer;
    size_t file_buffer_len;
} elf_exec_t;

elf_exec_t *elf_exec_new(uint8_t *code, size_t code_len);
void        elf_exec_destroy(elf_exec_t *e);
void        elf_exec_dump(elf_exec_t *e, char *file_path);

#endif
