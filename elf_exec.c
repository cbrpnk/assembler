#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf_exec.h"

#define ELF_HEADERS_MAXLEN 0x1000

void gen_file_buffer(elf_exec_t *e) {
    // Header
    Elf64_Ehdr *hdr = (Elf64_Ehdr *) &e->file_buffer[0];
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
    hdr->e_entry = 0x401000;
    hdr->e_phoff = sizeof(Elf64_Ehdr);
    hdr->e_shoff = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    hdr->e_flags = 0x0;
    hdr->e_ehsize = 0x40;
    hdr->e_phentsize = 0x38;
    hdr->e_phnum = 0x01;
    hdr->e_shentsize = 0x40;
    hdr->e_shnum = 0x03;
    hdr->e_shstrndx = 0x02;
    
    // New program header
    Elf64_Phdr *phdr = (Elf64_Phdr *) &e->file_buffer[hdr->e_phoff];
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R | PF_X;
    phdr->p_offset = 0x1000;
    phdr->p_vaddr = hdr->e_entry;
    phdr->p_paddr = hdr->e_entry;
    phdr->p_filesz = e->code_len;
    phdr->p_memsz = e->code_len;
    phdr->p_align = 0x1000;
    
    // .text section header
    Elf64_Shdr *shdr = (Elf64_Shdr *) &e->file_buffer[hdr->e_shoff];
    shdr++; // First section header is reserved
    shdr->sh_name = 0;
    shdr->sh_type = SHT_PROGBITS;
    shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    shdr->sh_addr = phdr->p_vaddr;
    shdr->sh_offset = phdr->p_offset;
    shdr->sh_size = e->code_len;
    shdr->sh_link = 0;
    shdr->sh_info = 0;
    shdr->sh_addralign = 4;
    shdr->sh_entsize = 0;
    
    // .text
    uint8_t *text = &e->file_buffer[phdr->p_offset];
    memcpy(text, e->code, e->code_len);
    
    // .shstrtab section header
    char symtable[100] = ".text\0.shstrtab";
    char symtable_len = 16;
    shdr++;
    
    shdr->sh_name = 6;
    shdr->sh_type = SHT_STRTAB;
    shdr->sh_flags = 0;
    shdr->sh_addr = 0;
    shdr->sh_offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + sizeof(Elf64_Shdr)*3;  // 0x1020;   // TODO Hardcoded
    shdr->sh_size = symtable_len;
    shdr->sh_link = 0;
    shdr->sh_info = 0;
    shdr->sh_addralign = 1;
    shdr->sh_entsize = 0;
    
    // .shstrtab
    memcpy(e->file_buffer+shdr->sh_offset, symtable, symtable_len);
}

elf_exec_t *elf_exec_new(uint8_t *code, size_t code_len)
{
    elf_exec_t *e = malloc(sizeof(elf_exec_t));
    e->code = code;
    e->code_len = code_len;
    e->file_buffer_len = ELF_HEADERS_MAXLEN + code_len;
    e->file_buffer = calloc(1, e->file_buffer_len);
    gen_file_buffer(e);
    return e;
}

void elf_exec_destroy(elf_exec_t *e)
{
    free(e->file_buffer);
    free(e);
}

void elf_exec_dump(elf_exec_t *e, char *file_path)
{
    FILE *f = fopen(file_path, "wb");
    fwrite(e->file_buffer, e->file_buffer_len, 1, f);
    fclose(f);
}
