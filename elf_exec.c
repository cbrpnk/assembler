#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf_exec.h"

elf_exec_t *elf_exec_new()
{
    elf_exec_t *e = calloc(1, sizeof(elf_exec_t));
    
    e->header_len = 0;
    e->program_header_len = 0;
    e->section_header_len = sizeof(Elf64_Shdr); // We skip the first entry as per spec
    e->sections = NULL;
    e->sections_len = 0;
    return e;
}

void elf_exec_destroy(elf_exec_t *e)
{
    free(e->sections);
    free(e);
}

void elf_exec_add_text(elf_exec_t *e, char *buff, size_t len,
                                uint64_t offset, uint64_t mem_offset) {
    // .text section header
    Elf64_Shdr *shdr = (Elf64_Shdr *) &e->section_header_table[e->section_header_len];
    shdr->sh_name = 7;
    shdr->sh_type = SHT_PROGBITS;
    shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    shdr->sh_addr = mem_offset + offset;
    shdr->sh_offset = ELF_FILE_SECTIONS_OFFSET + offset;
    shdr->sh_size = len;
    shdr->sh_link = 0;
    shdr->sh_info = 0;
    shdr->sh_addralign = 8;
    shdr->sh_entsize = 0;
    
    e->section_header_len += sizeof(Elf64_Shdr);
    
    // .text
    e->sections = realloc(e->sections, offset + len);
    memcpy(e->sections + offset, buff, len);
    e->sections_len = offset + len;;
    
    // Program header
    Elf64_Phdr *phdr = (Elf64_Phdr *) (e->program_header_table
                                    + e->program_header_len);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R | PF_X;
    phdr->p_offset = ELF_FILE_SECTIONS_OFFSET + offset;
    phdr->p_vaddr = mem_offset + offset;
    phdr->p_paddr = mem_offset + offset;
    phdr->p_filesz = len;
    phdr->p_memsz = len;
    phdr->p_align = 0x1000;
    
    e->program_header_len += sizeof(Elf64_Phdr);
}

void elf_exec_add_data(elf_exec_t *e, char *buff, size_t len,
                       uint64_t offset, uint64_t mem_offset) {
    // .data section header
    Elf64_Shdr *shdr = (Elf64_Shdr *) &e->section_header_table[e->section_header_len];
    shdr->sh_name = 1;
    shdr->sh_type = SHT_PROGBITS;
    shdr->sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr->sh_addr = mem_offset + offset;
    shdr->sh_offset = ELF_FILE_SECTIONS_OFFSET + offset;
    shdr->sh_size = len;
    shdr->sh_link = 0;
    shdr->sh_info = 0;
    shdr->sh_addralign = 8;
    shdr->sh_entsize = 0;
    
    e->section_header_len += sizeof(Elf64_Shdr);
    
    // Program header
    Elf64_Phdr *phdr = (Elf64_Phdr *) (e->program_header_table
                                    + e->program_header_len);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R;
    phdr->p_offset = ELF_FILE_SECTIONS_OFFSET + offset;
    phdr->p_vaddr = mem_offset + offset;
    phdr->p_paddr = mem_offset + offset;
    phdr->p_filesz = len;
    phdr->p_memsz = len;
    phdr->p_align = 0x1000;
    
    e->program_header_len += sizeof(Elf64_Phdr);
    
    // section
    e->sections = realloc(e->sections, offset + len);
    memcpy(e->sections + offset, buff, len);
    e->sections_len = offset + len;
}

void gen_header(elf_exec_t *e, uint64_t entry) {
    // Header
    Elf64_Ehdr *hdr = (Elf64_Ehdr *) e->header;
    hdr->e_ident[EI_MAG0] = ELFMAG0;
    hdr->e_ident[EI_MAG1] = ELFMAG1;
    hdr->e_ident[EI_MAG2] = ELFMAG2;
    hdr->e_ident[EI_MAG3] = ELFMAG3;
    hdr->e_ident[EI_CLASS] = ELFCLASS64;
    hdr->e_ident[EI_DATA] = ELFDATA2LSB;
    hdr->e_ident[EI_VERSION] = EV_CURRENT;
    hdr->e_ident[EI_OSABI] = ELFOSABI_LINUX;
    hdr->e_ident[EI_ABIVERSION] = 0x00;
    hdr->e_type = ET_EXEC;
    hdr->e_machine = EM_X86_64;
    hdr->e_version = EV_CURRENT;
    hdr->e_entry = entry;
    hdr->e_phoff = sizeof(Elf64_Ehdr);
    hdr->e_shoff = sizeof(Elf64_Ehdr) + e->program_header_len;
    hdr->e_flags = 0x0;
    hdr->e_ehsize = 0x40;
    hdr->e_phentsize = 0x38;
    hdr->e_phnum = 0x02;        // TODO Hardcoded
    hdr->e_shentsize = 0x40;
    hdr->e_shnum = 0x04;        // TODO Hardcoded
    hdr->e_shstrndx = 0x03;     // TODO Hardcoded
    
    e->header_len = sizeof(Elf64_Ehdr);
}

void gen_shstrtab(elf_exec_t *e) {
    char symtable[100] = "\0.data\0.text\0.shstrtab";
    size_t symtable_len = 22;
    
    Elf64_Shdr *shdr = (Elf64_Shdr *) &e->section_header_table[e->section_header_len];
    shdr->sh_name = 13;
    shdr->sh_type = SHT_STRTAB;
    shdr->sh_flags = 0;
    shdr->sh_addr = 0;
    shdr->sh_offset = ELF_FILE_SECTIONS_OFFSET + e->sections_len;
    shdr->sh_size = symtable_len;
    shdr->sh_link = 0;
    shdr->sh_info = 0;
    shdr->sh_addralign = 1;
    shdr->sh_entsize = 0;

    e->section_header_len += sizeof(Elf64_Shdr);
    
    // .shstrtab
    e->sections = realloc(e->sections, e->sections_len + symtable_len);
    memcpy(e->sections + e->sections_len, symtable, symtable_len);
    e->sections_len += symtable_len;
}

void elf_exec_dump(elf_exec_t *e, char *file_path,
                    uint64_t sections_file_offset, uint64_t entry)
{
    // Generate
    //gen_program_header(e);
    gen_shstrtab(e);
    gen_header(e, entry);
    
    // Calculate total file size
    size_t total_file_len =  ELF_FILE_SECTIONS_OFFSET + e->sections_len;
    uint8_t *output_buf = calloc(1, total_file_len);
    uint8_t *cursor = output_buf;
    
    // Header
    memcpy(cursor, e->header, e->header_len);
    cursor += e->header_len;
    
    // Program Header Table
    memcpy(cursor, e->program_header_table, e->program_header_len);
    cursor += e->program_header_len;
    
    // Section Header Table
    memcpy(cursor, e->section_header_table, e->section_header_len);
    cursor += e->section_header_len;
    
    // Sections
    cursor = output_buf + ELF_FILE_SECTIONS_OFFSET;
    memcpy(cursor, e->sections, e->sections_len);
    
    FILE *f = fopen(file_path, "wb");
    fwrite(output_buf, total_file_len, 1, f);
    
    free(output_buf);
    fclose(f);
}
