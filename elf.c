/* General layout: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format */
/* 32-bit layout: http://www.cs.cmu.edu/afs/cs/academic/class/15213-s00/doc/elf.pdf */
/* 64-bit layout: https://www.uclibc.org/docs/elf-64-gen.pdf */
/* x86_64 Relocation types: https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/chapter7-2/index.html */
/* PPC64 extension: http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.pdf */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <udis86.h> // X86 and X86_64 disassembler - probably should be in a separate .c file
#include "backend.h"

#pragma pack(1)

#define ALIGN(_x, _y) ((_x + (_y-1)) & ~(_y-1))
#define ELF_MAGIC "\x7F\x45\x4c\x46"
#define MAGIC_SIZE 4

#define ELF_SYMBOL_GLOBAL 0x0010
#define ELF_SYMBOL_WEAK 0x0020

#define ELF_SECTION_UNDEF 0
#define ELF_SECTION_ABS 0xFFF1
#define ELF_SECTION_COMMON 0xFFF2

#define ELF32_R_SYM(_x) (_x>>8)
#define ELF32_R_TYPE(_x) (_x & 0xFF)
#define ELF32_R_INFO(_s, _t) (unsigned int)((_s) << 8 | (_t && 0xFF))

#define ELF64_R_SYM(_x) (_x>>32)
#define ELF64_R_TYPE(_x) (_x & 0xFFFFFFFFL)
#define ELF64_R_INFO(_x, _t) (unsigned long)((unsigned long)(_x) << 32 | _t & ELF64_R_TYPE(_t))

/*
enum elf_sections
{
   SECTION_INDEX_NULL,        // NULL
   SECTION_INDEX_TEXT,        // .text
   SECTION_INDEX_RELA,        // .rela.text 
   SECTION_INDEX_DATA,        // .data
   SECTION_INDEX_RODATA,      // .rodata
   SECTION_INDEX_BSS,         // .bss
   SECTION_INDEX_SYMTAB,      // .symtab
   SECTION_INDEX_STRTAB,      // .strtab
   SECTION_INDEX_SHSTRTAB,    // .shstrtab
   SECTION_COUNT
};
*/

typedef enum elf_machine
{
   ELF_ISA_UNSPECIFIED,
   ELF_ISA_M32,         // AT&T WE 32100
   ELF_ISA_SPARC,
   ELF_ISA_X86,
   ELF_ISA_68K,
   ELF_ISA_88K,
   ELF_ISA_860,
   ELF_ISA_MIPS,
   ELF_ISA_POWERPC = 0x14,
   ELF_ISA_POWERPC_LE,
   ELF_ISA_S390,
   ELF_ISA_ARM = 0x28,
   ELF_ISA_SUPERH = 0x2A,
   ELF_ISA_IA64 = 0x32,
   ELF_ISA_X86_64 = 0x3E,
   ELF_ISA_AARCH64 = 0xB7,
   ELF_ISA_RISCV = 0xF3,
} elf_machine;

// OS
typedef enum os
{
   ELF_OS_SYSTEM_V,
   ELF_OS_HP_UX,
   ELF_OS_NET_BSD,
   ELF_OS_LINUX,
   ELF_OS_GNU_HURD,
   ELF_OS_SOLARIS,
   ELF_OS_AIX,
   ELF_OS_IRIX,
   ELF_OS_FREE_BSD,
   ELF_OS_TRU64,
   ELF_OS_NOVELL,
   ELF_OS_OPEN_BSD,
   ELF_OS_OPEN_VMS,
   ELF_OS_NONSTOP,
   ELF_OS_AROS,
   ELF_OS_FENIX,
   ELF_OS_CLOUD_ABI,
   ELF_OS_SORTIX = 0x53,
   ELF_OS_NONE = 0xff
} os;

typedef enum type
{
   ELF_TYPE_NONE,
   ELF_TYPE_RELOC,
   ELF_TYPE_EXEC,
   ELF_TYPE_SHARED,
   ELF_TYPE_CORE
} type;

typedef enum section_type
{
   SHT_NULL,
   SHT_PROGBITS,
   SHT_SYMTAB,
   SHT_STRTAB,
   SHT_RELA,
   SHT_HASH,
   SHT_DYNAMIC,
   SHT_NOTE,
   SHT_NOBITS,
   SHT_REL,
   SHT_SHLIB,
   SHT_DYNSYM,
} section_type;

// shift values for flags
#define SHF_WRITE 0
#define SHF_ALLOC 1
#define SHF_EXECINSTR 2
// 3 = x
// 4 = M (merge)
// 5 = S (strings)
#define SHF_INFO 6
// L
// G
// T
// E

enum elf_symbol_type
{
   ELF_ST_NOTYPE,
   ELF_ST_OBJECT,
   ELF_ST_FUNC,
   ELF_ST_SECTION,
   ELF_ST_FILE,
   ELF_ST_LOOS = 10,
   ELF_ST_HIOS = 12,
   ELF_ST_LOPROC = 13,
   ELF_ST_HIPROC = 15
};

typedef enum elf_x86_64_reloc_type
{
   R_AMD64_NONE,
   R_AMD64_64,
   R_AMD64_PC32,
   R_AMD64_GOT32,
   R_AMD64_PLT32,
   R_AMD64_COPY,
   R_AMD64_GLOB_DAT,
   R_AMD64_JUMP_SLOT,
   R_AMD64_RELATIVE,
   R_AMD64_GOTPCREL,
   R_AMD64_32,
   R_AMD64_32S,
   R_AMD64_16,
   R_AMD64_PC16,
   R_AMD64_8,
   R_AMD64_PC8,
   R_AMD64_PC64,
   R_AMD64_GOTOFF64,
   R_AMD64_GOTPC32,
   R_AMD64_SIZE32,
   R_AMD64_SIZE64
} elf_x86_64_reloc_type;

typedef enum elf_x86_reloc_type
{
   R_386_NONE,
   R_386_32,
   R_386_PC32,
   R_386_GOT32,
   R_386_PLT32,
   R_386_COPY,
   R_386_GLOB_DAT,
   R_386_JMP_SLOT,
   R_386_RELATIVE,
   R_386_GOTOFF,
   R_386_GOTPC
} elf_x86_reloc_type;

typedef struct elf32_header
{
   char magic[4];
   char class;       // 1=32 bit, 2=64 bit
   char endian;      // 1=little, 2=big
   char h_version;
   char os;          // see ELF_OS_
   char abi;
   char padding[7];
   short type;       // see ELF_TYPE_
   short machine;    // see ELF_MACHINE_
   unsigned int version;
   unsigned int entry;
   unsigned int ph_off; // program header offset
   unsigned int sh_off; // section header offset
   unsigned int flags;
   short eh_size;
   short phent_size;
   short ph_num;
   short shent_size;
   short sh_num;
   short sh_str_index;
} elf32_header;

typedef struct elf64_header
{
   char magic[4];
   char size;        // 1=32 bit, 2=64 bit
   char endian;      // 1=little, 2=big
   char h_version;
   char os;          // see ELF_OS_
   char abi;
   char padding[7];
   short type;       // see ELF_TYPE_
   short machine;    // see ELF_MACHINE_
   unsigned int version;
   unsigned long entry;
   unsigned long ph_off; // program header offset
   unsigned long sh_off; // section header offset
   unsigned int flags;
   short eh_size; // size of this struct in bytes = sizeof(elf64_header)
   short phent_size; // size of a program header
   short ph_num; // number of program headers
   short shent_size; // size of a section header = sizeof(elf64_section)
   short sh_num; // number of section headers
   short sh_str_index; // index of the string table section header
} elf64_header;

typedef struct elf32_section
{
   unsigned int name; // offset into the shstrtab string table
   unsigned int type; // see SHT_
   unsigned int flags; // see SHF_
   unsigned int addr;
   unsigned int offset; // offset of the section data in the file
   unsigned int size;
   unsigned int link;
   unsigned int info;
   unsigned int addralign;
   unsigned int entsize;
} elf32_section;

typedef struct elf32_symbol
{
   unsigned int name;
   unsigned int value;
   unsigned int size;
   unsigned char info; // see ELF_ST_
   unsigned char other;
   short section_index;
} elf32_symbol;

typedef struct elf32_rela
{
   unsigned int addr;
   unsigned int info; // see ELF_R_
   int addend;
} elf32_rela;

typedef struct elf64_section
{
   unsigned int name; // offset into the shstrtab string table
   unsigned int type; // see SHT_
   unsigned long flags; // see SHF_
   unsigned long addr;
   unsigned long offset; // offset of the section data in the file
   unsigned long size;
   unsigned int link;
   unsigned int info;
   unsigned long addralign;
   unsigned long entsize;
} elf64_section;

typedef struct elf64_symbol
{
   unsigned int name;
   unsigned char info; // see ELF_ST_
   unsigned char other;
   short section_index;
   unsigned long value;
   unsigned long size;
} elf64_symbol;

typedef struct elf64_rela
{
   unsigned long addr;
   unsigned long info; // see ELF_R_
   long addend;
} elf64_rela;

typedef struct elf_verneed_header
{
  unsigned short version;
  unsigned short count;
  unsigned int file;
  unsigned int aux;
  unsigned int next;
} elf_verneed_header;

typedef struct elf_verneed_entry
{
  unsigned int hash;
  unsigned short flags;
  unsigned short other;
  unsigned int name;
  unsigned int next;
} elf_verneed_entry;

struct item_name
{
   unsigned short id;
   char name[31+1];
};

static const struct item_name machine_lookup[] = 
{
   { ELF_ISA_UNSPECIFIED,    "Unknown machine" },
   { ELF_ISA_M32,       "AT&T WE 32100" },
   { ELF_ISA_SPARC,    "SPARC" },
   { ELF_ISA_X86,    "x86" },
   { ELF_ISA_68K,    "Motorola 68000" },
   { ELF_ISA_88K,    "Motorola 88000" },
   { ELF_ISA_860,    "Intel 80860" },
   { ELF_ISA_MIPS,    "MIPS RS3000" },
   { ELF_ISA_POWERPC,    "PowerPC" },
   { ELF_ISA_POWERPC_LE, "PowerPC LE" },
   { ELF_ISA_S390,    "IBM S390" },
   { ELF_ISA_ARM,    "ARM" },
   { ELF_ISA_SUPERH,    "SuperH" },
   { ELF_ISA_IA64,    "IA 64" },
   { ELF_ISA_X86_64,    "x86-64" },
   { ELF_ISA_AARCH64,    "AArch64" },
   { ELF_ISA_RISCV,    "RISC-V" },
};

static const struct item_name os_lookup[] = 
{
   { ELF_OS_SYSTEM_V, "SystemV" },
   { ELF_OS_HP_UX, "HP-UX" },
   { ELF_OS_NET_BSD, "NetBSD" },
   { ELF_OS_LINUX, "Linux" } ,
   { ELF_OS_GNU_HURD, "GNU Hurd" },
   { ELF_OS_SOLARIS, "Solaris" },
   { ELF_OS_AIX, "AIX" },
   { ELF_OS_IRIX, "IRIX" },
   { ELF_OS_FREE_BSD, "FreeBSD" },
   { ELF_OS_TRU64, "Tru64" },
   { ELF_OS_NOVELL, "Novell Modesto" },
   { ELF_OS_OPEN_BSD, "OpenBSD" },
   { ELF_OS_OPEN_VMS, "VMS" },
   { ELF_OS_NONSTOP, "Nonstop Kernel" },
   { ELF_OS_AROS, "AROS" },
   { ELF_OS_FENIX, "Fenix OS" },
   { ELF_OS_CLOUD_ABI, "CloudABI" },
   { ELF_OS_SORTIX, "Sortix" },
   { ELF_OS_NONE, "No OS" },
};

static const struct item_name type_lookup[] = 
{
   { ELF_TYPE_NONE, "None" },
   { ELF_TYPE_RELOC, "Relocatable" }, 
   { ELF_TYPE_EXEC, "Executable" },
   { ELF_TYPE_SHARED, "Shared" },
   { ELF_TYPE_CORE, "Core" },
};

static const struct item_name section_type_lookup[] =
{
   { SHT_NULL, "Bad section" },
   { SHT_PROGBITS, "Program" },
   { SHT_SYMTAB, "Symbol table" },
   { SHT_STRTAB, "String table" },
   { SHT_RELA, "Relocations" },
   { SHT_HASH, "Hash table" },
   { SHT_DYNAMIC, "Dynamic links" },
   { SHT_NOTE, "Notes" },
   { SHT_NOBITS, "No bits" },
   { SHT_REL, "Reclocations" },
   { SHT_SHLIB, "Weirdo" },
   { SHT_DYNSYM, "Dynamic symbols" },
};

static const char* flags_lookup[] = 
{
   "Does not contain base relocations and must therefore be loaded at its preferred base address",
};

static const char* section_flags_lookup[] = 
{
   "",
};

#define __lookup(_item, _table) \
   for (int i=0; i < sizeof(_table)/sizeof(struct item_name); i++) \
      if (_table[i].id == _item) \
         return _table[i].name; \
   return _table[0].name;

static const char* elf_lookup_type(enum type type)
{
   __lookup(type, type_lookup);
}

static const char* elf_lookup_os(enum os os)
{
   __lookup(os, os_lookup);
}

static const char* elf_lookup_machine(unsigned short machine)
{
   __lookup(machine, machine_lookup);
}

static const char* elf_lookup_section_type(unsigned short type)
{
   __lookup(type, section_type_lookup);
}

void dump_elf_header(const char* buf)
{
   elf64_header *e64 = (elf64_header*)buf;

   if (e64->size == 1)
   {
      printf("32-bit ELF header\n");
   }
   else if (e64->size == 2)
   {
      printf("64-bit ELF header\n");
      if (e64->endian == 1)
         printf("Little endian\n");
      else if (e64->endian == 2)
         printf("Big endian\n");
      else
         printf("Unknown endian %i\n", e64->endian);
      printf("Version: %i\n", e64->version);
   }
   else
   {
      printf("%i is not a known ELF size\n", e64->size);
   }

   printf("OS: %s\n", elf_lookup_os(e64->os));
   printf("Type: %s\n", elf_lookup_type(e64->type));
   printf("Machine: %s (%i)\n", elf_lookup_machine(e64->machine), e64->machine);
   printf("Entry point: 0x%lx\n", e64->entry);
   printf("Number of program headers: %i\n", e64->ph_num); 
}

void dump_elf64_section(elf64_section* s, const char* strtab)
{
   printf("Name: %s\n", strtab + s->name);
   printf("Type: %s\n", elf_lookup_section_type(s->type));
   printf("Flags: 0x%lx\n", s->flags);
   printf("Load address: 0x%lx\n", s->addr);
   printf("File Offset: 0x%lx\n", s->offset);
   printf("Size: 0x%lx\n", s->size);
   printf("Alignment: %i (%lu)\n", 2 << s->addralign, s->addralign);
   printf("Entry size: %lu\n\n", s->entsize);
}

const char* elf32_name(void)
{
   return "elf32";
}

const char* elf64_name(void)
{
   return "elf64";
}

/* identifies the file format we can read/write */
backend_type elf32_format(void)
{
   return OBJECT_TYPE_ELF32;
}

backend_type elf64_format(void)
{
   return OBJECT_TYPE_ELF64;
}

backend_symbol_type elf_to_backend_sym_type(unsigned char info)
{
   switch(info & 0x0F)
   {
   case ELF_ST_NOTYPE:
      return SYMBOL_TYPE_NONE;
   case ELF_ST_OBJECT:
      return SYMBOL_TYPE_OBJECT;
   case ELF_ST_FUNC:
      return SYMBOL_TYPE_FUNCTION;
   case ELF_ST_SECTION:
      return SYMBOL_TYPE_SECTION;
   case ELF_ST_FILE:
      return SYMBOL_TYPE_FILE;
   }

   return SYMBOL_TYPE_NONE;
}

unsigned char backend_to_elf_sym_type(backend_symbol_type t)
{
   switch(t)
   {
   case SYMBOL_TYPE_NONE:
      return ELF_ST_NOTYPE;
   case SYMBOL_TYPE_OBJECT:
      return ELF_ST_OBJECT;
   case SYMBOL_TYPE_FUNCTION:
      return ELF_ST_FUNC;
   case SYMBOL_TYPE_SECTION:
      return ELF_ST_SECTION;
   case SYMBOL_TYPE_FILE:
      return ELF_ST_FILE;
   }

   return ELF_ST_NOTYPE;
}

elf_x86_reloc_type backend_to_elf32_reloc_type(backend_reloc_type t)
{
   switch(t)
   {
   case RELOC_TYPE_OFFSET:
      return R_386_32;
   case RELOC_TYPE_PC_RELATIVE:
      return R_386_PC32;
   }

   return R_386_NONE;
}

elf_x86_64_reloc_type backend_to_elf64_reloc_type(backend_reloc_type t)
{
   switch(t)
   {
   case RELOC_TYPE_OFFSET:
      return R_AMD64_32;
   case RELOC_TYPE_PC_RELATIVE:
      return R_AMD64_PC32;
   }

   return R_AMD64_NONE;
}

int elf_reloc_addend(elf_x86_64_reloc_type t)
{
   if (t == R_AMD64_PC32)
      return -4;

   return 0;
}

static long decode_plt_entry(elf_machine m, const char* plt_entry)
{
   ud_t ud_obj;
   ud_init(&ud_obj);

   //printf("Looking up at %p\n", plt_entry);
   switch(m)
   {
   case ELF_ISA_X86:
      ud_set_mode(&ud_obj, 32); // decode in 32 bit mode
      break;

   case ELF_ISA_X86_64:
      ud_set_mode(&ud_obj, 64);
      break;

   default:
      return -1;
   }

   // decode that entry
   enum ud_mnemonic_code mnem;
   unsigned bytes;
   ud_set_input_buffer(&ud_obj, plt_entry, 0x10);
   bytes = ud_disassemble(&ud_obj); // the 'jump' to the GOT
   //bytes = ud_disassemble(&ud_obj); // the 'push'
   //bytes = ud_disassemble(&ud_obj); // then the 'jump'to PLT start
   mnem = ud_insn_mnemonic(&ud_obj);
   if (mnem != UD_Ijmp)
   {
      printf("PLT instruction is not jump\n");
      return -1;
   }

   const struct ud_operand* op = ud_insn_opr(&ud_obj, 0);
   if (!op)
      return -2;

   //printf("%lx: %s\n", plt_addr, ud_lookup_mnemonic(mnem));
   //printf("OP: %x %p %x\n", op->lval.sdword, plt_entry, bytes);
   
   return op->lval.sdword;
}

// read the section headers sequentially from the file, looking for a specific section name
int elf64_find_section(FILE* f, const elf64_header* h, const char* name, const char* strtab, elf64_section* s)
{
   for (int i=0; i < h->sh_num; i++)
   {
      fseek(f, h->sh_off + h->shent_size * i, SEEK_SET);
      fread(s, h->shent_size, 1, f);

      if (strcmp(strtab + s->name, name) == 0)
         return i;
   }

   return -1;
}

static backend_object* elf32_read_file(FILE* f, elf32_header* h)
{
   backend_object* obj = backend_create();
   if (!obj)
      return 0;

   return obj;
}

static backend_object* elf64_read_file(FILE* f, elf64_header* h)
{
   elf64_section in_sec;

   backend_object* obj = backend_create();
   if (!obj)
      return 0;

   backend_set_type(obj, OBJECT_TYPE_ELF64);

   printf("Number of section headers: %i\n", h->sh_num); 
   printf("Size of section headers: %i\n", h->shent_size); 
   printf("String table index: %i\n", h->sh_str_index);

	backend_set_entry_point(obj, h->entry);

   // first, preload the section header string table
   fseek(f, h->sh_off + h->shent_size * h->sh_str_index, SEEK_SET);
   fread(&in_sec, h->shent_size, 1, f);

   char* section_strtab = malloc(in_sec.size);
   fseek(f, in_sec.offset, SEEK_SET);
   fread(section_strtab, in_sec.size, 1, f);
   
   //printf("ELF64: Adding sections\n");
   // load sections
   for (int i=1; i < h->sh_num; i++)
   { 
      fseek(f, h->sh_off + h->shent_size * i, SEEK_SET);
      fread(&in_sec, h->shent_size, 1, f);

      char* name = section_strtab + in_sec.name;
      if (!backend_get_section_by_name(obj, name))
      {
         unsigned long flags=0;
         char* data = malloc(in_sec.size);

         fseek(f, in_sec.offset, SEEK_SET);
         fread(data, in_sec.size, 1, f);

         // set flags for known sections by name
         if (strcmp(name, ".text") == 0)
            flags = SECTION_FLAG_CODE;
         if (strcmp(name, ".init") == 0)
            flags = SECTION_FLAG_CODE;
         else if (strcmp(name, ".data") == 0)
            flags = SECTION_FLAG_INIT_DATA;
         else if (strcmp(name, ".rodata") == 0)
            flags = SECTION_FLAG_INIT_DATA;
         else if (strcmp(name, ".bss") == 0)
            flags = SECTION_FLAG_UNINIT_DATA;
         else
         {
            if (in_sec.flags & SHF_EXECINSTR)
               flags = SECTION_FLAG_CODE;
            if (in_sec.flags & SHF_ALLOC && !(in_sec.flags & SHF_EXECINSTR) && (!in_sec.flags & SHF_WRITE))
               flags = SECTION_FLAG_INIT_DATA;
            if (in_sec.flags & SHF_ALLOC && !(in_sec.flags & SHF_EXECINSTR)) // not exactly accurate - better to set these flags according to section name
               flags = SECTION_FLAG_UNINIT_DATA;
         }
         backend_add_section(obj, name, in_sec.size, in_sec.addr, data, in_sec.entsize, in_sec.addralign, flags);
      }
   }

   // now that we have the raw data, try to format it as objects the backend can understand (strings, symbols, sections, relocs, etc)
   backend_section* sec_strtab = backend_get_section_by_name(obj, ".strtab");
   if (!sec_strtab)
   {
      printf("Can't find string table section!\n");
      goto done;
   }

   // create symbols
   backend_section* sec_symtab = backend_get_section_by_name(obj, ".symtab");
   if (!sec_symtab)
   {
      printf("Can't find symbol table section!\n");
      goto done;
   }
   elf64_symbol* sym = (elf64_symbol*)sec_symtab->data;
   //printf("Symbol table size: %i entry size: %i\n", sec_symtab->size, sec_symtab->entry_size);
   for (int i=0; i < sec_symtab->size/sec_symtab->entry_size; i++)
   {
      if (sym->name)
      {  
         backend_section* sec;
         char* name = sec_strtab->data + sym->name;

         // try to determine the section that this symbol belongs to
         if (sym->section_index <= 0 || sym->section_index == ELF_SECTION_ABS || sym->section_index == ELF_SECTION_COMMON)
         {
            //printf("Setting NULL section\n");
            sec = NULL;
         }
         else
            sec = backend_get_section_by_index(obj, sym->section_index);

         //printf("Symbol %s has section %i (%s)\n", name, sym->section_index, sec?sec->name:NULL);
         backend_add_symbol(obj, name, sym->value, elf_to_backend_sym_type(sym->info), sym->size, 0, sec);
      }
      sym++;
   }

   // since we are dealing with dynamic symbols, we will need access to the dynamic symbol table, dynamic string table and version tables
   backend_section* sec_dynsym = backend_get_section_by_name(obj, ".dynsym");
   if (!sec_dynsym)
   {
      printf("Can't find .dynsym\n");
      goto done;
   }

   backend_section* sec_dynstr = backend_get_section_by_name(obj, ".dynstr");
   if (!sec_dynstr)
   {
      printf("Can't find .dynstr\n");
      goto done;
   }

   backend_section* sec_versym = backend_get_section_by_name(obj, ".gnu.version");
   if (!sec_versym)
   {
      printf("Can't find .gnu.version\n");
      goto done;
   }

   backend_section* sec_versymr = backend_get_section_by_name(obj, ".gnu.version_r");
   if (!sec_versymr)
   {
      printf("Can't find .gnu.version_r\n");
      goto done;
   }

   backend_section* sec_text = backend_get_section_by_name(obj, ".text");
   if (!sec_text)
   {
      printf("Can't find code section!\n");
      goto done;
   }

   backend_section* sec_plt = backend_get_section_by_name(obj, ".plt");
   if (!sec_plt)
   {
      printf("Can't find PLT section!\n");
      goto done;
   }

   // Create dynamic symbols
   // Code is linked using addresses in the PLT section. We want to have a symbol at that address
   // so we can look up by address when disassembling code.
   backend_section* sec_rela = backend_get_section_by_name(obj, ".rela.plt");
   if (!sec_rela)
   {
      printf("Can't find PLT reloc section!\n");
      goto done;
   }

   char sym_name[64];
   elf64_rela* rela = (elf64_rela*)sec_rela->data;
   elf64_symbol* dsym = (elf64_symbol*)sec_dynsym->data;
   unsigned short* ver = (unsigned short*)sec_versym->data;
   elf_verneed_header* versymr = (elf_verneed_header*)sec_versymr->data;
   elf_verneed_entry* verent = (elf_verneed_entry*)(sec_versymr->data + versymr->aux);
   for (int i=0; i < sec_rela->size/sec_rela->entry_size; i++)
   {
      // we must look up this symbol by index in the ELF dynamic symbol table
      unsigned long index = ELF64_R_SYM(rela->info);

      //printf("Getting dynsym index=%lu\n", index);
      dsym = (elf64_symbol*)sec_dynsym->data + index;
      //printf("dynsym @ %p dsym @ %p\n", sec_dynsym->data, dsym);
      strcpy(sym_name, sec_dynstr->data + dsym->name);
      printf("Found symbol name %s at offset 0x%lx\n", sym_name, rela->addr);

      backend_add_symbol(obj, sym_name, rela->addr, SYMBOL_TYPE_FUNCTION, 0, SYMBOL_FLAG_EXTERNAL, sec_text);
      
      // get the version number to look up the version string
      ver = (unsigned short*)sec_versym->data + index;
      //printf("Version %u\n", *ver);
      //printf("Ver: %i Count: %i File: %s\n", versymr->version, versymr->count, versymr->file + sec_dynstr->data);
      //printf("Name: %s Flags: %i Version: %i\n", verent->name + sec_dynstr->data, verent->flags, verent->other);
      char* module_name = NULL;
      if (*ver == verent->other)
         module_name = sec_dynstr->data + verent->name;

      if (module_name)
      {
         backend_import* mod = backend_find_import_module_by_name(obj, module_name);
         if (!mod)
            mod = backend_add_import_module(obj, module_name);
         if (mod)
         {
            backend_section* sec = backend_find_section_by_val(obj, rela->addr);
            //printf("0x%lx is in section %s\n", rela->addr, sec->name);
            unsigned long plt_addr = *(unsigned long*)(sec->data + (rela->addr - sec->address));
            unsigned long sym_addr = plt_addr - 6;
            //printf("Address: 0x%lx\n", sym_addr);
            //sec = backend_find_section_by_val(obj, plt_addr);
            //printf("0x%lx is in section %s\n", plt_addr, sec->name);
            //long sym_addr = decode_plt_entry(ELF_ISA_X86_64, (char*)(sec->data + (plt_addr - sec->address) - 6)) + plt_addr;
            printf("Adding import function %s @ 0x%lx\n", sym_name, sym_addr);
            backend_add_import_function(mod, sym_name, sym_addr);
         }

         // now get the corresponding symbol from the main table and delete it
         strcat(sym_name, "@@");
         strcat(sym_name, module_name);
         printf("Removing original PLT symbol %s (%i)\n", sym_name, backend_symbol_count(obj));
         backend_remove_symbol_by_name(obj, sym_name);
         printf("After: %i\n", backend_symbol_count(obj));
      }

      rela++;
   }
   

done:
   free(section_strtab);

   printf("ELF64 loading done (%i symbols, %i relocs)\n", backend_symbol_count(obj), backend_relocation_count(obj));
   printf("-----------------------------------------\n");

   return obj;
}

static backend_object* elf_read_file(const char* filename)
{
   backend_object* obj = NULL;
   char* buff = malloc(sizeof(elf64_header));

   FILE* f = fopen(filename, "rb");
   if (!f)
   {
      printf("can't open file\n");
      goto done;
   }

   // get size of the file
   fseek(f, 0, SEEK_END);
   int fsize = ftell(f);

   // read enough data for the ELF64 header, and then figure out dynamically which one we've got
   fseek(f, 0, SEEK_SET);
   fread(buff, sizeof(elf64_header), 1, f);
   if (memcmp(buff, ELF_MAGIC, MAGIC_SIZE) != 0)
      goto done;
   
   dump_elf_header(buff);
   
   elf64_header* h = (elf64_header*)buff;

   // load the rest of the data
   if (h->size == 1)
      obj = elf32_read_file(f, (elf32_header*)buff);
   else if (h->size == 2)
      obj = elf64_read_file(f, (elf64_header*)buff);
   else
      printf("Unknown ELF size: %i (not 32-bit, not 64-bit)\n", h->size);

done:
   free(buff);
   
   return obj;
}

static int elf32_write_file(backend_object* obj, const char* filename)
{
   backend_section *bs;
   elf32_header fh;
   elf32_section sh;
   unsigned int shstrtab_size = 1000;
   unsigned int strtab_size = 4096;

   //printf("elf32_write_file\n");

   FILE* f = fopen(filename, "wb");
   if (!f)
   {
      printf("can't open file\n");
      return -1;
   }

   // before anything, ensure the backend object isn't missing anything, and is ready to be written
   
   // if there are any relocations, we must have a .rela.text section
   if (backend_relocation_count(obj) > 0)
   {
      if (!backend_get_section_by_name(obj, ".rela.text"))
         bs = backend_add_section(obj, ".rela.text", 0, 0, 0, 0, 0, 0);
   }

   // if there are any sections, we must have a section header string table
   if (backend_section_count(obj) > 0)
   {
      if (!backend_get_section_by_name(obj, ".shstrtab"))
         bs = backend_add_section(obj, ".shstrtab", 0, 0, 0, 0, 0, 0);
   }

   // if there are any symbols, we will need a symbol table & string table
   if (backend_symbol_count(obj) > 0)
   {
      if (!backend_get_section_by_name(obj, ".symtab"))
         bs = backend_add_section(obj, ".symtab", 0, 0, 0, 0, 0, 0);
      if (!backend_get_section_by_name(obj, ".strtab"))
         bs = backend_add_section(obj, ".strtab", 0, 0, 0, 0, 0, 0);
   }

   // write file header
   memset(&fh, 0, sizeof(elf32_header));
   memcpy(fh.magic, ELF_MAGIC, MAGIC_SIZE);
   fh.class = 1;
   fh.endian = 1;
   fh.h_version = 1;
   fh.os = ELF_OS_SYSTEM_V;
   fh.type = ELF_TYPE_RELOC; // object code
   fh.machine = ELF_ISA_X86; // this should be taken from the backend object
   fh.version = 1;
   fh.sh_off = sizeof(elf32_header);
   fh.eh_size = sizeof(elf32_header); 
   fh.shent_size = sizeof(elf32_section);
   fh.sh_num = backend_section_count(obj) + 1; // first section is null
   fh.sh_str_index = backend_get_section_index_by_name(obj, ".shstrtab");
   //printf("shstrtab index = %i\n", fh.sh_str_index);
   fwrite(&fh, sizeof(elf32_header), 1, f);

   // so we know where to write the next object
   int fpos_cur;
   int fpos_data = fh.sh_off + fh.shent_size*fh.sh_num;

   // build the section header string table with the names we need
   char* shstrtab = malloc(shstrtab_size); // just need enough space for a few strings
   char* shstrtab_entry = shstrtab+1;
   shstrtab[0] = 0; // the initial entry is always 0
   bs = backend_get_first_section(obj);
   while (bs)
   {
      bs->_name = shstrtab_entry - shstrtab;
      // enter the name in the string table
      strcpy(shstrtab_entry, bs->name);
      shstrtab_entry += strlen(shstrtab_entry) + 1;
      if (shstrtab_entry - shstrtab > shstrtab_size)
      {
         printf("Exceeded section header string table size\n");
      }
      bs = backend_get_next_section(obj);
   }

   // build the symbol string table as well
   char* strtab = malloc(strtab_size);
   char* strtab_entry = strtab+1;
   strtab[0] = 0; // the initial entry is always 0

   // write the null section header
   //printf("write null section header\n");
   memset(&sh, 0, sizeof(elf32_section));
   fwrite(&sh, sizeof(elf32_section), 1, f);

   // loop over all sections in the backend object, and write them (header & contents)
   bs = backend_get_first_section(obj);
   while (bs)
   {
      sh.addr = 0;
      sh.size = 0;
      sh.offset = 0;
      sh.addralign = 1;
      sh.link = 0;
      sh.info = 0;
      sh.entsize = 0;
      sh.name = bs->_name;

      if (strcmp(".text", bs->name) == 0)
      {
         // write the .text section & header
         printf("Writing .text section\n");
         sh.type = SHT_PROGBITS;
         sh.flags = (1<<SHF_ALLOC) | (1<<SHF_EXECINSTR);
         sh.addr = bs->address;
         sh.size = bs->size;
         sh.addralign = bs->alignment;
         if (sh.size)
         {
            sh.offset = ALIGN(fpos_data, sh.addralign);
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(bs->data, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".rela.text", bs->name) == 0)
      {
         // write the .rela section header
         printf("Writing .rela.text section\n");
         sh.type = SHT_RELA;
         sh.flags = (1<<SHF_INFO);
         sh.link = backend_get_section_index_by_name(obj, ".symtab"); // which symbol table to use
         if (sh.link == -1)
            printf("Error getting .symtab index\n");
         sh.info = backend_get_section_index_by_name(obj, ".text"); // which code is relevant
         if (sh.info == -1)
            printf("Error getting .text index\n");
         sh.entsize = sizeof(elf32_rela);
         sh.size = backend_relocation_count(obj) * sizeof(elf32_rela);
         sh.addralign = 8;
         if (sh.size)
         {
            sh.offset = ALIGN(fpos_data, sh.addralign);
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            backend_reloc* r = backend_get_first_reloc(obj);
            while (r)
            {
               elf32_rela rela;
               rela.addr = r->offset;
               unsigned int reloc_type = backend_to_elf32_reloc_type(r->type);
               rela.info = ELF32_R_INFO(backend_get_symbol_index(obj, r->symbol)+1, reloc_type); // elf has 1 null symbol at the beginning
               rela.addend = r->addend;
               //printf("writing reloc for 0x%x symbol: %s (%u) addend: 0x%x type=%u\n", rela.addr, r->symbol->name, backend_get_symbol_index(obj, r->symbol)+1, rela.addend, reloc_type);
               fwrite(&rela, sizeof(elf32_rela), 1, f);
               r = backend_get_next_reloc(obj);
            }
            fpos_data = ftell(f);
            fseek(f, fpos_cur, SEEK_SET);
         }
      }
      else if (strcmp(".data", bs->name) == 0)
      {
         // write the .data section header
         printf("Writing .data section\n");
         sh.type = SHT_PROGBITS;
         sh.flags = (1<<SHF_ALLOC) | (1<<SHF_WRITE);
         sh.addr = bs->address;
         sh.size = bs->size;
         sh.addralign = bs->alignment;
         if (sh.size)
         {
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(bs->data, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".bss", bs->name) == 0)
      {
         // write the .bss section header
         printf("Writing .bss section\n");
         sh.type = SHT_NOBITS;
         sh.flags = (1<<SHF_ALLOC) | (1<<SHF_WRITE);
         sh.addr = bs->address;
         sh.size = bs->size;
         sh.addralign = bs->alignment;
         if (sh.size)
         {
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(bs->data, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".rodata", bs->name) == 0)
      {
         // write the .rodata section header
         printf("Writing .rodata section\n");
         sh.type = SHT_PROGBITS;
         sh.flags = (1<<SHF_ALLOC);
         sh.addr = bs->address;
         sh.size = bs->size;
         sh.addralign = bs->alignment;
         if (sh.size)
         {
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(bs->data, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".symtab", bs->name) == 0)
      {
         backend_symbol* sym;
         int text_index = backend_get_section_index_by_name(obj, ".text");
         // write the .symtab section header
         printf("Writing .symtab section\n");
         sh.type = SHT_SYMTAB;
         sh.link = backend_get_section_index_by_name(obj, ".strtab"); // which string table to use
         if (sh.link == -1)
            printf("Error getting .symtab index\n");
         // info contains the index of the first non-local symbol
         sym = backend_get_symbol_by_type_first(obj, SYMBOL_TYPE_FUNCTION);
         if (sym)
         {
            sh.info = backend_get_symbol_index(obj, sym) + 1; // add 1 for the null symbol
            printf("First global symbol index %i\n", sh.info);
         }

         //printf("symtab index=%i\n", sh.link);
         sh.entsize = sizeof(elf32_symbol);
         sh.size = (backend_symbol_count(obj) + 1) * sizeof(elf32_symbol); // add 1 for the null symbol
         sh.addralign = 8;
         if (sh.size)
         {
            elf32_symbol s={0};
            fpos_data = ALIGN(fpos_data, sh.addralign);
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            printf("We have %u symbols\n", backend_symbol_count(obj)+1);
            fseek(f, sh.offset, SEEK_SET);
      
            // write an empty symbol first
            fwrite(&s, sizeof(elf32_symbol), 1, f);

            // now the rest of the symbols
            sym = backend_get_first_symbol(obj);
            while (sym)
            {
               s.name = strtab_entry - strtab;
               s.info = backend_to_elf_sym_type(sym->type);
               s.other = 0;
               s.section_index = text_index; // link the symbol to the .text section
               s.value = sym->val;
               s.size = sym->size;

               //printf("Writing symbol %s\n", sym->name);

               // take into account any flags set in the backend
               if (sym->flags & SYMBOL_FLAG_GLOBAL)
                  s.info |= ELF_SYMBOL_GLOBAL;
               if (sym->flags & SYMBOL_FLAG_EXTERNAL)
                  s.section_index = ELF_SECTION_UNDEF;

               // if this is an external function, it can't have an address
               if (sym->type == SYMBOL_TYPE_NONE &&
                  sym->flags & (SYMBOL_FLAG_GLOBAL | SYMBOL_FLAG_EXTERNAL))
                  s.value = 0;

               // if this is a section symbol, make sure the index is updated to the correct section
               if (sym->type == SYMBOL_TYPE_SECTION)
               {
                  //printf("Writing section symbol %s\n", sym->name);
                  s.section_index = backend_get_section_index_by_name(obj, sym->name); // which section does this symbol relate to
                  if (s.section_index == -1)
                  {
                     printf("Error getting %s index\n", sym->name);
                     sym = backend_get_next_symbol(obj);
                     continue;
                  }
                  //sym->name = 0;
                  //s.name = 0;
               }

               if (sym->type == SYMBOL_TYPE_FILE)
                  s.section_index = ELF_SECTION_ABS;

               if (sym->name)
               {
                  if (strtab_entry - strtab + strlen(sym->name) > strtab_size)
                  {
                     unsigned int offset = strtab_entry - strtab;
                     strtab_size += 4096;
                     printf("Exceeded string table size - extending to %u\n", strtab_size);
                     strtab = realloc(strtab, strtab_size);
                     strtab_entry = strtab + offset;
                  }
                  strcpy(strtab_entry, sym->name);
                  strtab_entry += strlen(strtab_entry) + 1;
               }
               fwrite(&s, sizeof(elf32_symbol), 1, f);
               sym = backend_get_next_symbol(obj);
            }
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".strtab", bs->name) == 0)
      {
         // write the .strtab section header
         sh.type = SHT_STRTAB;
         sh.size = strtab_entry - strtab;
         printf("Writing .strtab section (%u)\n", sh.size);
         if (sh.size)
         {
            // align fpos_data
            fpos_data = ALIGN(fpos_data, sh.addralign);
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(strtab, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".shstrtab", bs->name) == 0)
      {
         // write the .shstrtab section header
         printf("Writing .shstrtab section\n");
         sh.type = SHT_STRTAB;
         sh.offset = fpos_data;
         sh.size = shstrtab_entry - shstrtab;

         // write the data of the section header string table
         if (sh.size)
         {
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(shstrtab, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }

      fwrite(&sh, sizeof(elf32_section), 1, f);

      bs = backend_get_next_section(obj);
   }

done:
   free(shstrtab);
   free(strtab);
   fclose(f);
   return 0;
}

static int elf64_write_file(backend_object* obj, const char* filename)
{
   backend_section *bs;
   elf64_header fh;
   elf64_section sh;
   unsigned int shstrtab_size = 1000;
   unsigned int strtab_size = 4096;

   //printf("elf64_write_file\n");

   FILE* f = fopen(filename, "wb");
   if (!f)
   {
      printf("can't open file\n");
      return -1;
   }

   // before anything, ensure the backend object isn't missing anything, and is ready to be written
   
   // if there are any relocations, we must have a .rela.text section
   if (backend_relocation_count(obj) > 0)
   {
      if (!backend_get_section_by_name(obj, ".rela.text"))
         bs = backend_add_section(obj, ".rela.text", 0, 0, 0, 0, 0, 0);
   }

   // if there are any sections, we must have a section header string table
   if (backend_section_count(obj) > 0)
   {
      if (!backend_get_section_by_name(obj, ".shstrtab"))
         bs = backend_add_section(obj, ".shstrtab", 0, 0, 0, 0, 0, 0);
   }

   // if there are any symbols, we will need a symbol table & string table
   if (backend_symbol_count(obj) > 0)
   {
      if (!backend_get_section_by_name(obj, ".symtab"))
         bs = backend_add_section(obj, ".symtab", 0, 0, 0, 0, 0, 0);
      if (!backend_get_section_by_name(obj, ".strtab"))
         bs = backend_add_section(obj, ".strtab", 0, 0, 0, 0, 0, 0);
   }

   // write file header
   memset(&fh, 0, sizeof(elf64_header));
   memcpy(fh.magic, ELF_MAGIC, MAGIC_SIZE);
   fh.size = 2;
   fh.endian = 1;
   fh.h_version = 1;
   fh.os = ELF_OS_SYSTEM_V;
   fh.type = ELF_TYPE_RELOC; // object code
   fh.machine = ELF_ISA_X86_64; // this should be taken from the backend object
   fh.version = 1;
   fh.sh_off = sizeof(elf64_header);
   fh.eh_size = sizeof(elf64_header); 
   fh.shent_size = sizeof(elf64_section);
   fh.sh_num = backend_section_count(obj) + 1; // first section is null
   fh.sh_str_index = backend_get_section_index_by_name(obj, ".shstrtab");
   //printf("shstrtab index = %i\n", fh.sh_str_index);
   fwrite(&fh, sizeof(elf64_header), 1, f);

   // so we know where to write the next object
   int fpos_cur;
   int fpos_data = fh.sh_off + fh.shent_size*fh.sh_num;

   // build the section header string table with the names we need
   char* shstrtab = malloc(shstrtab_size); // just need enough space for a few strings
   char* shstrtab_entry = shstrtab+1;
   shstrtab[0] = 0; // the initial entry is always 0
   bs = backend_get_first_section(obj);
   while (bs)
   {
      bs->_name = shstrtab_entry - shstrtab;
      // enter the name in the string table
      strcpy(shstrtab_entry, bs->name);
      shstrtab_entry += strlen(shstrtab_entry) + 1;
      if (shstrtab_entry - shstrtab > shstrtab_size)
      {
         printf("Exceeded section header string table size\n");
      }
      bs = backend_get_next_section(obj);
   }

   // build the symbol string table as well
   char* strtab = malloc(strtab_size);
   char* strtab_entry = strtab+1;
   strtab[0] = 0; // the initial entry is always 0

   // write the null section header
   //printf("write null section header\n");
   memset(&sh, 0, sizeof(elf64_section));
   fwrite(&sh, sizeof(elf64_section), 1, f);

   // loop over all sections in the backend object, and write them (header & contents)
   bs = backend_get_first_section(obj);
   while (bs)
   {
      sh.addr = 0;
      sh.size = 0;
      sh.offset = 0;
      sh.addralign = 1;
      sh.link = 0;
      sh.info = 0;
      sh.entsize = 0;
      sh.name = bs->_name;

      if (strcmp(".text", bs->name) == 0)
      {
         // write the .text section & header
         printf("Writing .text section\n");
         sh.type = SHT_PROGBITS;
         sh.flags = (1<<SHF_ALLOC) | (1<<SHF_EXECINSTR);
         sh.addr = bs->address;
         sh.size = bs->size;
         sh.addralign = bs->alignment;
         if (sh.size)
         {
            sh.offset = ALIGN(fpos_data, sh.addralign);
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(bs->data, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".rela.text", bs->name) == 0)
      {
         // write the .rela section header
         printf("Writing .rela.text section\n");
         sh.type = SHT_RELA;
         sh.flags = (1<<SHF_INFO);
         sh.link = backend_get_section_index_by_name(obj, ".symtab"); // which symbol table to use
         if (sh.link == -1)
            printf("Error getting .symtab index\n");
         sh.info = backend_get_section_index_by_name(obj, ".text"); // which code is relevant
         if (sh.info == -1)
            printf("Error getting .text index\n");
         sh.entsize = sizeof(elf64_rela);
         sh.size = backend_relocation_count(obj) * sizeof(elf64_rela);
         sh.addralign = 8;
         if (sh.size)
         {
            sh.offset = ALIGN(fpos_data, sh.addralign);
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            backend_reloc* r = backend_get_first_reloc(obj);
            while (r)
            {
               elf64_rela rela;
               rela.addr = r->offset;
               unsigned int reloc_type = backend_to_elf64_reloc_type(r->type);
               rela.info = ELF64_R_INFO(backend_get_symbol_index(obj, r->symbol)+1, reloc_type); // elf has 1 null symbol at the beginning
               rela.addend = r->addend;
               //printf("writing reloc for 0x%lx symbol: %s (%u) addend: 0x%lx\n", rela.addr, r->symbol->name, backend_get_symbol_index(obj, r->symbol)+1, rela.addend);
               fwrite(&rela, sizeof(elf64_rela), 1, f);
               r = backend_get_next_reloc(obj);
            }
            fpos_data = ftell(f);
            fseek(f, fpos_cur, SEEK_SET);
         }
      }
      else if (strcmp(".data", bs->name) == 0)
      {
         // write the .data section header
         printf("Writing .data section\n");
         sh.type = SHT_PROGBITS;
         sh.flags = (1<<SHF_ALLOC) | (1<<SHF_WRITE);
         sh.addr = bs->address;
         sh.size = bs->size;
         sh.addralign = bs->alignment;
         if (sh.size)
         {
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(bs->data, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".bss", bs->name) == 0)
      {
         // write the .bss section header
         printf("Writing .bss section\n");
         sh.type = SHT_NOBITS;
         sh.flags = (1<<SHF_ALLOC) | (1<<SHF_WRITE);
         sh.addr = bs->address;
         sh.size = bs->size;
         sh.addralign = bs->alignment;
         if (sh.size)
         {
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(bs->data, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".rodata", bs->name) == 0)
      {
         // write the .rodata section header
         printf("Writing .rodata section\n");
         sh.type = SHT_PROGBITS;
         sh.flags = (1<<SHF_ALLOC);
         sh.addr = bs->address;
         sh.size = bs->size;
         sh.addralign = bs->alignment;
         if (sh.size)
         {
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(bs->data, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".symtab", bs->name) == 0)
      {
         backend_symbol* sym;
         int text_index = backend_get_section_index_by_name(obj, ".text");
         // write the .symtab section header
         printf("Writing .symtab section\n");
         sh.type = SHT_SYMTAB;
         sh.link = backend_get_section_index_by_name(obj, ".strtab"); // which string table to use
         if (sh.link == -1)
            printf("Error getting .symtab index\n");
         // info contains the index of the first non-local symbol
         sym = backend_get_symbol_by_type_first(obj, SYMBOL_TYPE_FUNCTION);
         if (sym)
         {
            sh.info = backend_get_symbol_index(obj, sym) + 1; // add 1 for the null symbol
            printf("First global symbol index %i\n", sh.info);
         }

         //printf("symtab index=%i\n", sh.link);
         sh.entsize = sizeof(elf64_symbol);
         sh.size = (backend_symbol_count(obj) + 1) * sizeof(elf64_symbol); // add 1 for the null symbol
         sh.addralign = 8;
         if (sh.size)
         {
            elf64_symbol s={0};
            fpos_data = ALIGN(fpos_data, sh.addralign);
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            printf("We have %u symbols\n", backend_symbol_count(obj)+1);
            fseek(f, sh.offset, SEEK_SET);
      
            // write an empty symbol first
            fwrite(&s, sizeof(elf64_symbol), 1, f);

            // now the rest of the symbols
            sym = backend_get_first_symbol(obj);
            while (sym)
            {
               s.name = strtab_entry - strtab;
               s.info = backend_to_elf_sym_type(sym->type);
               s.other = 0;
               s.section_index = text_index; // link the symbol to the .text section
               s.value = sym->val;
               s.size = sym->size;

               //printf("Writing symbol %s\n", sym->name);

               // take into account any flags set in the backend
               if (sym->flags & SYMBOL_FLAG_GLOBAL)
                  s.info |= ELF_SYMBOL_GLOBAL;
               if (sym->flags & SYMBOL_FLAG_EXTERNAL)
                  s.section_index = ELF_SECTION_UNDEF;

               // if this is an external function, it can't have an address
               if (sym->type == SYMBOL_TYPE_NONE &&
                  sym->flags & (SYMBOL_FLAG_GLOBAL | SYMBOL_FLAG_EXTERNAL))
                  s.value = 0;

               // if this is a section symbol, make sure the index is updated to the correct section
               if (sym->type == SYMBOL_TYPE_SECTION)
               {
                  //printf("Writing section symbol %s\n", sym->name);
                  s.section_index = backend_get_section_index_by_name(obj, sym->name); // which section does this symbol relate to
                  if (s.section_index == -1)
                  {
                     printf("Error getting %s index\n", sym->name);
                     sym = backend_get_next_symbol(obj);
                     continue;
                  }
                  //sym->name = 0;
                  //s.name = 0;
               }

               if (sym->type == SYMBOL_TYPE_FILE)
                  s.section_index = ELF_SECTION_ABS;

               if (sym->name)
               {
                  if (strtab_entry - strtab + strlen(sym->name) > strtab_size)
                  {
                     unsigned int offset = strtab_entry - strtab;
                     strtab_size += 4096;
                     printf("Exceeded string table size - extending to %u\n", strtab_size);
                     strtab = realloc(strtab, strtab_size);
                     strtab_entry = strtab + offset;
                  }
                  strcpy(strtab_entry, sym->name);
                  strtab_entry += strlen(strtab_entry) + 1;
               }
               fwrite(&s, sizeof(elf64_symbol), 1, f);
               sym = backend_get_next_symbol(obj);
            }
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".strtab", bs->name) == 0)
      {
         // write the .strtab section header
         sh.type = SHT_STRTAB;
         sh.size = strtab_entry - strtab;
         printf("Writing .strtab section (%lu)\n", sh.size);
         if (sh.size)
         {
            // align fpos_data
            fpos_data = ALIGN(fpos_data, sh.addralign);
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(strtab, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".shstrtab", bs->name) == 0)
      {
         // write the .shstrtab section header
         printf("Writing .shstrtab section\n");
         sh.type = SHT_STRTAB;
         sh.offset = fpos_data;
         sh.size = shstrtab_entry - shstrtab;

         // write the data of the section header string table
         if (sh.size)
         {
            sh.offset = fpos_data;
            fpos_cur = ftell(f);
            fseek(f, sh.offset, SEEK_SET);
            fwrite(shstrtab, sh.size, 1, f);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }

      fwrite(&sh, sizeof(elf64_section), 1, f);

      bs = backend_get_next_section(obj);
   }

done:
   free(shstrtab);
   free(strtab);
   fclose(f);
   return 0;
}

backend_ops elf32_backend =
{
   .name = elf32_name,
   .format = elf32_format,
   .read = elf_read_file,
   .write = elf32_write_file
};

backend_ops elf64_backend =
{
   .name = elf64_name,
   .format = elf64_format,
   .read = elf_read_file,
   .write = elf64_write_file
};

void elf32_init(void)
{
   backend_register(&elf32_backend);
}

void elf64_init(void)
{
   backend_register(&elf64_backend);
}
