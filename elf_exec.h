#ifndef ELF_EXEC_H
#define ELF_EXEC_H

#include <stdint.h>
#include <elf.h>

#define ELF_HEADER_MAXLEN               1024
#define ELF_PROGRAM_HEADER_TABLE_MAXLEN 1024
#define ELF_SECTION_HEADER_TABLE_MAXLEN 1024
#define ELF_FILE_SECTIONS_OFFSET 0x1000


/*
 *  sections [data_section | padding to 0x1000 | text | shstrtab]
 *  
 *  
 *
 *
 */
typedef struct {
    // This is where in the files the actual sections will be layed down
    uint64_t sections_file_offset;
    
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
void        elf_exec_add_text(elf_exec_t *e, char *buff, size_t len,
                                uint64_t offset, uint64_t mem_offset);
void        elf_exec_add_data(elf_exec_t *e, char *buff, size_t len,
                                uint64_t offset, uint64_t mem_offset);
void        elf_exec_dump(elf_exec_t *e, char *file_path,
                    uint64_t sections_file_offset, uint64_t entry);

#endif
