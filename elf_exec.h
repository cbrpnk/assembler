#ifndef ELF_EXEC_H
#define ELF_EXEC_H

#include <stdint.h>
#include <elf.h>

#define ELF_HEADER_MAXLEN               1024
#define ELF_PROGRAM_HEADER_TABLE_MAXLEN 1024
#define ELF_SECTION_HEADER_TABLE_MAXLEN 1024
#define ELF_FILE_ENTRY 0x1000
#define ELF_MEM_ENTRY  0x401000

typedef struct {
    uint8_t  header[ELF_HEADER_MAXLEN];
    size_t   header_len;
    uint8_t  program_header_table[ELF_PROGRAM_HEADER_TABLE_MAXLEN];
    size_t   program_header_len;
    uint8_t  section_header_table[ELF_SECTION_HEADER_TABLE_MAXLEN];
    size_t   section_header_len;
    uint8_t *sections;
    size_t   sections_len;
} elf_exec_t;

elf_exec_t *elf_exec_new();
void        elf_exec_destroy(elf_exec_t *e);
void        elf_exec_add_text(elf_exec_t *e, char *buff, size_t len);
void        elf_exec_add_data(elf_exec_t *e, char *buff, size_t len);
void        elf_exec_dump(elf_exec_t *e, char *file_path);

#endif
