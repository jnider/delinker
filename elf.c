/* General layout: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format */
/* 32-bit layout: https://refspecs.linuxbase.org/elf/elf.pdf */
/* 64-bit layout: https://www.uclibc.org/docs/elf-64-gen.pdf */
/* x86_64 Relocation types: https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/chapter7-2/index.html */
/* PPC64 extension: http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.pdf */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "capstone/capstone.h"
#include "backend.h"
#include "config.h"

#pragma pack(1)

#ifdef DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT //
#endif

#define ALIGN(_x, _y) ((_x + (_y-1)) & ~(_y-1))
#define ELF_MAGIC "\x7F\x45\x4c\x46"
#define MAGIC_SIZE 4
#define SYMBOL_MAX_LENGTH 127

#define ELF_SYMBOL_GLOBAL	0x10
#define ELF_SYMBOL_WEAK		0x20

#define ELF_SECTION_UNDEF 0
#define ELF_SECTION_ABS 0xFFF1
#define ELF_SECTION_COMMON 0xFFF2

#define ELF_SYM_TYPE(_x) (_x & 0xF) // lower 4 bits from the info field
//#define ELF_SYM_SCOPE(_x) ((_x>>4) & 0xF) // upper 4 bits from the info field

#define ELF32_R_SYM(_x) (_x>>8)
#define ELF32_R_TYPE(_x) (unsigned int)(_x & 0xFF)
#define ELF32_R_INFO(_s, _t) (unsigned int)((_s) << 8 | (_t && 0xFF))

#define ELF64_R_SYM(_x) (unsigned int)(_x>>32)
#define ELF64_R_TYPE(_x) (unsigned int)(_x & 0xFFFFFFFFL)
#define ELF64_R_INFO(_x, _t) (unsigned long)((unsigned long)(_x) << 32 | _t & ELF64_R_TYPE(_t))

#define IS_NULL_SYMBOL(_x) (\
	(_x->type == SYMBOL_TYPE_NONE) && \
	(_x->size == 0) && \
	(_x->val == 0) && \
	(_x->name[0] == 0))

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
typedef enum elf_os
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
} elf_os;

typedef enum elf_type
{
   ELF_TYPE_NONE,
   ELF_TYPE_RELOC,
   ELF_TYPE_EXEC,
   ELF_TYPE_SHARED,
   ELF_TYPE_CORE
} elf_type;

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

enum dynamic_tag
{
	DT_NULL,
	DT_NEEDED,
	DT_PLTRELSZ,
	DT_PLTGOT,
	DT_HASH,
	DT_STRTAB,
	DT_SYMTAB,
	DT_RELA,
	DT_RELASZ,
	DT_RELAENT,
	DT_STRSZ,	// 10
	DT_SYMENT,
	DT_INIT,
	DT_FINI,
	DT_SONAME,
	DT_RPATH,
	DT_SYMBOLIC,
	DT_REL,
	DT_RELSZ,
	DT_RELENT,
	DT_PLTREL, 	// 20
	DT_DEBUG,
	DT_TEXTREL,
	DT_JMPREL,
	DT_BINDNOW,
	DT_INIT_ARRAY,
	DT_FINI_ARRAY,
	DT_INIT_ARRAYSZ,
	DT_FINI_ARRAYSZ,
	DT_RUNPATH,
	DT_FLAGS,	// 30
	DT_ENCODING,
	DT_PREINIT_ARRAY,
	DT_PREINIT_ARRAYSZ,
	DT_MAXPOSTARGS,
	DT_LOOS=0x60000000,
	DT_LOPROC=0x70000000,
	DT_VERDEF=0x6ffffffc,
	DT_VERDEFNUM,
	DT_VERNEED,
	DT_VERNEEDNUM,
};

typedef struct elf32_header
{
   char magic[4];
   char classtype;   // 1=32 bit, 2=64 bit
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
   unsigned long info; // see ELF64_R_
   long addend;
} elf64_rela;

typedef struct elf_verneed_header
{
  unsigned short version; // version number of this struct (must be 1)
  unsigned short count;
  unsigned int file;
  unsigned int aux;
  unsigned int next;
} elf_verneed_header;

typedef struct elf_verneed_aux
{
  unsigned int hash;
  unsigned short flags;
  unsigned short other;
  unsigned int name;
  unsigned int next;
} elf_verneed_aux;

struct item_name
{
   unsigned short id;
   char name[31+1];
};

typedef struct elf64_dyn
{
	unsigned long d_tag;
	union
	{
		unsigned long d_val;
		unsigned long d_ptr;
	};
} elf64_dyn;

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

static const char* elf_lookup_type(enum elf_type type)
{
   __lookup(type, type_lookup);
}

static const char* elf_lookup_os(enum elf_os os)
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

#ifdef DEBUG
void dump_elf_header(const char* buf)
{
   elf64_header *e64 = (elf64_header*)buf;

   if (e64->size == 1)
   {
      fprintf(stderr, "32-bit ELF header\n");
   }
   else if (e64->size == 2)
   {
      fprintf(stderr, "64-bit ELF header\n");
      if (e64->endian == 1)
         fprintf(stderr, "Little endian\n");
      else if (e64->endian == 2)
         fprintf(stderr, "Big endian\n");
      else
         fprintf(stderr, "Unknown endian %i\n", e64->endian);
      fprintf(stderr, "Version: %i\n", e64->version);
   }
   else
   {
      fprintf(stderr, "%i is not a known ELF size\n", e64->size);
   }

   fprintf(stderr, "OS: %s\n", elf_lookup_os((elf_os)e64->os));
   fprintf(stderr, "Type: %s\n", elf_lookup_type((elf_type)e64->type));
   fprintf(stderr, "Machine: %s (%i)\n", elf_lookup_machine(e64->machine), e64->machine);
   fprintf(stderr, "Entry point: 0x%lx\n", e64->entry);
   fprintf(stderr, "Number of program headers: %i\n", e64->ph_num);
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

void dump_elf64_symbol(elf64_symbol *s, const unsigned char *strtab)
{
	printf("Name: %s\n", strtab + s->name);
	printf("Info: %u\n", s->info);
	printf("Other: %u\n", s->other);
	printf("Section index: %i\n", s->section_index);
	printf("Value: 0x%lx\n", s->value);
	printf("Size: 0x%lx\n", s->value);
}

void dump_rela(elf64_rela *rela)
{
	printf("Addr: 0x%lx\n", rela->addr);
	printf("Info: 0x%lx\n", rela->info);
	printf("  Type: 0x%x\n", ELF64_R_TYPE(rela->info));
	printf("  Sym: 0x%x\n", ELF64_R_SYM(rela->info));
	printf("Addend: 0x%lx\n", rela->addend);
}
#endif // DEBUG

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
   case RELOC_TYPE_PLT:
      return R_AMD64_PLT32;
   }

   return R_AMD64_NONE;
}

backend_section_type elf_to_backend_section_type(section_type t)
{
	switch(t)
	{
   case SHT_NULL:
		return SECTION_TYPE_NULL;
   case SHT_PROGBITS:
		return SECTION_TYPE_PROG;
   case SHT_SYMTAB:
		return SECTION_TYPE_SYMTAB;
   case SHT_STRTAB:
		return SECTION_TYPE_STRTAB;
   case SHT_RELA:
		return SECTION_TYPE_RELA;
   case SHT_HASH:
		return SECTION_TYPE_NULL;
   case SHT_DYNAMIC:
		return SECTION_TYPE_DYNSYM;
   case SHT_NOTE:
		return SECTION_TYPE_NOTE;
   case SHT_NOBITS:
		return SECTION_TYPE_NOBITS;
   case SHT_REL:
		return SECTION_TYPE_REL;
   case SHT_SHLIB:
		return SECTION_TYPE_NULL;
   case SHT_DYNSYM:
		return SECTION_TYPE_SYMTAB;
	}
	return SECTION_TYPE_NULL;
}

int elf_reloc_addend(elf_x86_64_reloc_type t)
{
   if (t == R_AMD64_PC32)
      return -4;

   return 0;
}

// this should be moved to the backend - it has nothing to do with elf
static unsigned long decode_plt_entry_x86_64(csh cs_dis, cs_insn *cs_ins, const unsigned char *pc, uint64_t pc_addr, unsigned long entry_size)
{
	cs_disasm_iter(cs_dis, &pc, &entry_size, &pc_addr, cs_ins);
	//printf("id: %u %s\n", cs_ins->id, cs_ins->mnemonic);
	if (cs_ins->id == X86_INS_ENDBR64)
	{
		cs_disasm_iter(cs_dis, &pc, &entry_size, &pc_addr, cs_ins);
		//printf("id: %u %s\n", cs_ins->id, cs_ins->mnemonic);
		if (cs_ins->id == X86_INS_PUSH)
		{
			return 0;
		}
		else if (cs_ins->id == X86_INS_JMP)
		{
			// extract the target address that should point to the GOT
			// The jump instruction is actually relative to the PC, so we must add
			// the current instruction address when looking it up.
			unsigned long target = *(unsigned int*)&cs_ins->bytes[3];
			target += pc_addr;
			return target;
		}
	}
	return 0;
}

// read the section headers sequentially from the file, looking for a specific section name
int elf64_find_section(FILE* f, const elf64_header* h, const char* name, const char* strtab, elf64_section* s)
{
   for (int i=0; i < h->sh_num; i++)
   {
      fseek(f, h->sh_off + h->shent_size * i, SEEK_SET);
		if (fread(s, h->shent_size, 1, f) != 1)
			return -2;

      if (strcmp(strtab + s->name, name) == 0)
         return i;
   }

   return -1;
}

/* Used to compare two symbols when sorting symbol table
   in order to write them to an ELF object file */
static int elfcmp(void* item_a, void* item_b)
{
	backend_symbol *a = (backend_symbol*)item_a;
	backend_symbol *b = (backend_symbol*)item_b;

	// ELF symbol ordering is like this:
	// 1. A null symbol (singleton)
	// 2. File symbol for this object file (singleton)
	// 3. Section symbols (local)
	// 4. Other locals (can sometimes intermingle with sections)
	// 5. global functions
	// 6. other globals

	// check to see if it is a null symbol. If so, it doesn't matter
	// what B is, because null symbols are all the same (actually there
	// should only be 1) and they must come before any other symbol.
	if (IS_NULL_SYMBOL(a))
		return 0;

	// if A is a file symbol, it must come after any null symbols,
	// but before anything else.
	else if (a->type == SYMBOL_TYPE_FILE)
	{
		if (IS_NULL_SYMBOL(b))
			return 1;
		else if (b->type == SYMBOL_TYPE_FILE)
			return 0;
		else
			return -1;
	}

	// All section symbols come after the file symbol. They are
	// considered equal, and sometimes their indices are out of
	// order (which is legal, but bothers me).
	else if (a->type == SYMBOL_TYPE_SECTION)
	{
		if (IS_NULL_SYMBOL(b))
			return 1;
		else if (b->type == SYMBOL_TYPE_FILE)
			return 1;
		else if (b->type == SYMBOL_TYPE_SECTION)
		{
			return 0;
		}
		else
			return -1;
	}

	else if (!(a->flags & SYMBOL_FLAG_GLOBAL))
	{
		if (!(b->flags & SYMBOL_FLAG_GLOBAL))
			return 0;
		return -1;
	}
	else
	{
		if (!(b->flags & SYMBOL_FLAG_GLOBAL))
			return 1;
		if (a->type == SYMBOL_TYPE_FUNCTION)
		{
			if (b->type == SYMBOL_TYPE_FUNCTION)
				return 0;
			else
				return -1;
		}
		return -1;
	}

	return 0;
}

static backend_object* elf32_read_file(FILE* f, elf32_header* h)
{
	char sym_name[SYMBOL_MAX_LENGTH+1];
	backend_arch be_arch;
	elf32_section in_sec;
	backend_section* sec_symtab;
	backend_section* sec_dynsym;
	backend_section* sec_dynstr;
	backend_section* sec_versym;
	backend_section* sec_versymr;
	backend_section* sec_text;
	backend_section* sec_rela;
	backend_section* sec_relaplt;
	backend_section* sec_strtab = NULL;
	elf32_symbol* dsym;
	elf32_symbol* sym;
	elf32_rela* rela;
	unsigned short* ver;
	elf_verneed_header* versymr;
	elf_verneed_aux* verent;
	char* section_strtab = NULL;
	char *src_file = NULL;

	printf("elf32_read_file\n");
	backend_object* obj = backend_create();
	if (!obj)
		return 0;

	backend_set_type(obj, OBJECT_TYPE_ELF32);
	switch (h->machine)
	{
	case ELF_ISA_X86:
		be_arch = OBJECT_ARCH_X86;
		break;

	case ELF_ISA_ARM:
		be_arch = OBJECT_ARCH_ARM;
		break;

	default:
		be_arch = OBJECT_ARCH_UNKNOWN;
	}
	if (config.verbose)
		fprintf(stderr, "Arch %i\n", be_arch);
	backend_set_arch(obj, be_arch);

	if (config.verbose)
	{
		fprintf(stderr, "Number of section headers: %i\n", h->sh_num);
		fprintf(stderr, "Size of section headers: %i\n", h->shent_size);
		fprintf(stderr, "String table index: %i\n", h->sh_str_index);
	}

	backend_set_entry_point(obj, h->entry);

	// validate the size of the section entry struct
	if (h->shent_size != sizeof(elf32_section))
	{
		printf("Size mismatch in section: read %i expected %lu\n",
			h->shent_size, sizeof(elf32_section));
	}

	// first, preload the section header string table
	fseek(f, h->sh_off + h->shent_size * h->sh_str_index, SEEK_SET);
	if (fread(&in_sec, h->shent_size, 1, f) != 1)
	{
		fprintf(stderr, "Error loading string table\n");
		goto error;
	}

	section_strtab = (char*)malloc(in_sec.size);
	fseek(f, in_sec.offset, SEEK_SET);
	if (fread(section_strtab, in_sec.size, 1, f) != 1)
		goto error_strtab;

	// load sections
	for (int i=1; i < h->sh_num; i++)
	{
		fseek(f, h->sh_off + h->shent_size * i, SEEK_SET);
		if (fread(&in_sec, h->shent_size, 1, f) != 1)
			goto error_strtab;

		// if a section with this name doesn't already exist, add it
		char* name = section_strtab + in_sec.name;
		if (!backend_get_section_by_name(obj, name))
		{
			unsigned long flags=0;
			unsigned char* data = NULL;

			// load the section data unless it is marked as unloadable
			if (in_sec.type != SHT_NOBITS)
			{
				data = (unsigned char*)malloc(in_sec.size);

				fseek(f, in_sec.offset, SEEK_SET);
				if (fread(data, in_sec.size, 1, f) != 1)
				{
					fprintf(stderr, "Error loading section %s data\n", name);
					free(data);
					goto error_strtab;
				}
			}

			// set flags for known sections by name
			backend_section_type t;
			if (strcmp(name, ".text") == 0)
				flags = SECTION_FLAG_EXECUTE;
			else if (strcmp(name, ".init") == 0)
				flags = SECTION_FLAG_EXECUTE;
			else if (strcmp(name, ".data") == 0)
				flags = SECTION_FLAG_INIT_DATA;
			else if (strcmp(name, ".rodata") == 0)
				flags = SECTION_FLAG_INIT_DATA;
			else if (strcmp(name, ".bss") == 0)
				flags = SECTION_FLAG_UNINIT_DATA;
			else
			{
				if (in_sec.flags & SHF_EXECINSTR)
					flags = SECTION_FLAG_EXECUTE;
				if (in_sec.flags & SHF_ALLOC && !(in_sec.flags & SHF_EXECINSTR) && (!in_sec.flags & SHF_WRITE))
					flags = SECTION_FLAG_INIT_DATA;
				if (in_sec.flags & SHF_ALLOC && !(in_sec.flags & SHF_EXECINSTR)) // not exactly accurate - better to set these flags according to section name
					flags = SECTION_FLAG_UNINIT_DATA;
			}

			backend_section *s = backend_add_section(obj, name, in_sec.size, in_sec.addr, data, in_sec.entsize, in_sec.addralign, flags);
			backend_section_set_type(s, elf_to_backend_section_type((section_type)in_sec.type));
		}
	}

	// now that we have the raw data, try to format it as objects the backend can understand (strings, symbols, sections, relocs, etc)
	sec_strtab = backend_get_section_by_name(obj, ".strtab");
	if (!sec_strtab)
	{
		sec_strtab = backend_get_section_by_type(obj, SECTION_TYPE_STRTAB);
		if (!sec_strtab)
			printf("Warning: can't find string table section!\n");
		//goto done;
	}

	// create symbols
	sec_symtab = backend_get_section_by_name(obj, ".symtab");
	if (!sec_symtab)
	{
		sec_symtab = backend_get_section_by_type(obj, SECTION_TYPE_SYMTAB);
		if (!sec_symtab)
			printf("Warning: can't find symbol table section!\n");
		goto dynsym;
	}

	// Add each symbol to the backend object
	sym = (elf32_symbol*)sec_symtab->data;
	for (int i=0; i < sec_symtab->size/sec_symtab->entry_size; i++, sym++)
	{
		const char* name = NULL;
		backend_section* sec = NULL;
		backend_symbol *s;
		int symbol_flags=0;

		// get the symbol name
		if (sym->name && sec_strtab)
			name = (char*)sec_strtab->data + sym->name;

		switch (ELF_SYM_TYPE(sym->info))
		{
		case ELF_ST_NOTYPE:
			// The first symbol in an ELF file must have no name and no type
			//printf("Skipping symbol with no type\n");
			if (!backend_add_symbol(obj, name, 0, elf_to_backend_sym_type(sym->info), 0, 0, sec_symtab))
				printf("Failed adding untyped symbol\n");
			continue;

		case ELF_ST_SECTION:
			sec = backend_get_section_by_index(obj, sym->section_index);
			if (!backend_add_symbol(obj, sec->name, 0, elf_to_backend_sym_type(sym->info), 0, 0, sec) || !sec)
				printf("Failed adding section symbol\n");
			//printf("Adding section symbol %s (%i)\n", sec->name, sym->section_index);
			continue;

		case ELF_ST_FILE:
			// set this as the owning file for subsequent symbols
			if (src_file)
				free(src_file);
			if (!name)
			{
				//printf("Found unnamed file symbol\n");
				name = "_global.c";
			}
			//else
			//	printf("Found file symbol %s\n", name);
			src_file = strdup(name);
			break;
		}

		// try to determine the section that this symbol belongs to
		if (sym->section_index <= 0 ||
			sym->section_index == ELF_SECTION_ABS ||
			sym->section_index == ELF_SECTION_COMMON)
		{
			sec = NULL;
		}
		else
		{
			sec = backend_get_section_by_index(obj, sym->section_index);
			//printf("Symbol %s is in section %i (%s)\n", name, sym->section_index, sec->name);
		}

		// set the symbol scope
		if (sym->info & ELF_SYMBOL_GLOBAL)
			symbol_flags |= SYMBOL_FLAG_GLOBAL;

		// add the symbol
		s = backend_add_symbol(obj, name, sym->value, elf_to_backend_sym_type(sym->info), sym->size, symbol_flags, sec);
		if (!s)
		{
			// error adding symbol
		}

		// Some formats contain information relating symbols to the source file
		// that originally defined them. If we have that information, save it in
		// the backend object.
		if (src_file)
		{
			backend_set_source_file(s, src_file);
			//printf("Adding symbol %s to %s\n", name, src_file);
		}
	}

dynsym:
	// Since we are dealing with dynamic symbols, we will need access to the dynamic
	// symbol table, dynamic string table and version tables
	sec_dynsym = backend_get_section_by_name(obj, ".dynsym");
	if (!sec_dynsym)
	{
		printf("Can't find dynamic symbol section (.dynsym)\n");
		goto done;
	}

	sec_dynstr = backend_get_section_by_name(obj, ".dynstr");
	if (!sec_dynstr)
	{
		printf("Can't find .dynstr\n");
		goto done;
	}

	sec_versym = backend_get_section_by_name(obj, ".gnu.version");
	if (!sec_versym)
	{
		printf("Can't find .gnu.version\n");
		goto done;
	}

	sec_versymr = backend_get_section_by_name(obj, ".gnu.version_r");
	if (!sec_versymr)
	{
		printf("Can't find .gnu.version_r\n");
		goto done;
	}

	sec_text = backend_get_section_by_name(obj, ".text");
	if (!sec_text)
	{
		printf("Can't find code section!\n");
		goto done;
	}

	// Create dynamic symbols
	// Code is linked using addresses in the PLT section. We want to have a symbol at that address
	// so we can look up by address when disassembling code.
	sec_rela = backend_get_section_by_type(obj, SECTION_TYPE_REL);
	if (!sec_rela)
	{
		printf("Can't find PLT reloc section!\n");
		goto done;
	}

	// make sure there are dynamic symbol versions
	rela = (elf32_rela*)sec_rela->data;
	dsym = (elf32_symbol*)sec_dynsym->data;
	ver = (unsigned short*)sec_versym->data;
	versymr = (elf_verneed_header*)sec_versymr->data;
	verent = (elf_verneed_aux*)(sec_versymr->data + versymr->aux);
	if (!rela || !dsym || !ver || !versymr)
		goto done;

	// Each dynamic symbol has a relocation in .rela.plt
	for (int i=0; i < sec_rela->size/sec_rela->entry_size; i++)
	{
		// we must look up this symbol by index in the ELF dynamic symbol table
		unsigned long index = ELF32_R_SYM(rela->info);

		//DEBUG_PRINT("Getting dynsym index=%lu\n", index);
		dsym = (elf32_symbol*)sec_dynsym->data + index;
		//printf("dynsym @ %p dsym @ %p\n", sec_dynsym->data, dsym);
		strncpy(sym_name, (char*)sec_dynstr->data + dsym->name, SYMBOL_MAX_LENGTH);
		if (strlen((char*)sec_dynstr->data + dsym->name) > SYMBOL_MAX_LENGTH)
		{
			printf("warning: symbol name %s will be truncated!\n", sym_name);
			sym_name[SYMBOL_MAX_LENGTH] = 0;
		}
		//printf("Found symbol name %s at offset 0x%lx\n", sym_name, rela->addr);

		if (!backend_add_symbol(obj, sym_name, rela->addr, SYMBOL_TYPE_FUNCTION, 0, SYMBOL_FLAG_GLOBAL | SYMBOL_FLAG_EXTERNAL, sec_text))
			printf("Error adding %s\n", sym_name);

		char* module_name = (char*)sec_dynstr->data + verent->name;
		if (module_name)
		{
			//printf("Looking for module %s\n", module_name);
			backend_import* mod = backend_find_import_module_by_name(obj, module_name);
			if (!mod)
				mod = backend_add_import_module(obj, module_name);
			if (mod)
			{
				backend_section* sec = backend_find_section_by_val(obj, rela->addr);
				if (sec)
				{
					unsigned long plt_addr = *(unsigned long*)(sec->data + (rela->addr - sec->address));
					unsigned long sym_addr = plt_addr - 6; // why 6?
					if (!backend_add_import_function(mod, sym_name, sym_addr))
						printf("Error adding import function %s\n", sym_name);
				}
				else
				{
					printf("Error finding section for address 0x%x\n", rela->addr);
				}
			}
		}
		else
		{
			printf("  No import module\n");
		}

		rela++;
	}

done:
	free(section_strtab);

	printf("ELF32 loading done (%i symbols, %i relocs)\n", backend_symbol_count(obj), backend_relocation_count(obj));
	printf("-----------------------------------------\n");
	return obj;

error_strtab:
	free(section_strtab);
error:
	backend_destructor(obj);
	return NULL;
	return obj;
}

void elf64_add_import_from_rela(backend_object *obj, elf64_rela* rela, backend_section *sec_symtab, backend_section *sec_strtab, backend_section *sec_versymr)
{
   char sym_name[SYMBOL_MAX_LENGTH+1];
   elf64_symbol* dsym;
   elf_verneed_aux* verent;
   elf_verneed_header* versymr;

   versymr = (elf_verneed_header*)sec_versymr->data;
   verent = (elf_verneed_aux*)(sec_versymr->data + versymr->aux);

	// look up this symbol by index in the ELF dynamic symbol table to get the name
	unsigned int index = ELF64_R_SYM(rela->info);
	dsym = (elf64_symbol*)sec_symtab->data + index;
	strncpy(sym_name, (char*)sec_strtab->data + dsym->name, SYMBOL_MAX_LENGTH);
	if (strlen((char*)sec_symtab->data + dsym->name) > SYMBOL_MAX_LENGTH)
	{
		printf("Warning: symbol name %s will be truncated!\n", sym_name);
		sym_name[SYMBOL_MAX_LENGTH] = 0;
	}
	DEBUG_PRINT("Found dynamic symbol name %s at offset 0x%lx info: 0x%lx\n", sym_name, rela->addr, rela->info);

	char* module_name = (char*)sec_strtab->data + verent->name;
	if (module_name)
	{
		backend_import* mod = backend_find_import_module_by_name(obj, module_name);
		if (!mod)
			mod = backend_add_import_module(obj, module_name);

		if (mod)
		{
			printf("Adding import function %s@%s\n", sym_name, module_name);
			if (!backend_add_import_function(mod, sym_name, rela->addr))
				printf("Error adding import function %s@%s\n", sym_name, module_name);
		}
		else
			printf("  Error adding import module %s\n", module_name);
	}
	else
	{
		printf("  No import module\n");
	}
}

static backend_object* elf64_read_file(FILE* f, elf64_header* h)
{
	backend_arch be_arch;
	elf64_section in_sec;
	backend_section* sec_symtab;
	backend_section* sec_dynsym;
	backend_section* sec_dynstr;
	backend_section* sec_versymr;
	backend_section* sec_text;
	backend_section* sec_dynamic;
	backend_section* sec_reladyn;
	backend_section* sec_relaplt;
	backend_section* sec_got;
	backend_section* sec_strtab = NULL;
	backend_section* sec;
   elf64_symbol* sym;
   elf64_rela* rela;
	elf64_dyn *dyn_entry;
	char* section_strtab = NULL;
	char *src_file = NULL;
	backend_symbol* imp;

   backend_object* obj = backend_create();
   if (!obj)
      return 0;

   backend_set_type(obj, OBJECT_TYPE_ELF64);
   switch (h->machine)
   {
   case ELF_ISA_X86:
	case ELF_ISA_X86_64:
      be_arch = OBJECT_ARCH_X86;
      break;

   case ELF_ISA_ARM:
      be_arch = OBJECT_ARCH_ARM;
      break;

   case ELF_ISA_AARCH64:
      be_arch = OBJECT_ARCH_ARM64;
      break;

   default:
      be_arch = OBJECT_ARCH_UNKNOWN;
   }
   if (config.verbose)
		fprintf(stderr, "Arch %i\n", be_arch);
   backend_set_arch(obj, be_arch);

   if (config.verbose)
   {
      fprintf(stderr, "Number of section headers: %i\n", h->sh_num);
      fprintf(stderr, "Size of section headers: %i\n", h->shent_size);
      fprintf(stderr, "String table index: %i\n", h->sh_str_index);
   }

	backend_set_entry_point(obj, h->entry);

	// validate the size of the section entry struct
	if (h->shent_size != sizeof(elf64_section))
	{
		printf("Size mismatch in section: read %i expected %lu\n",
			h->shent_size, sizeof(elf64_section));
	}

   // first, preload the section header string table
   fseek(f, h->sh_off + h->shent_size * h->sh_str_index, SEEK_SET);
   if (fread(&in_sec, h->shent_size, 1, f) != 1)
	{
		fprintf(stderr, "Error loading string table\n");
		goto error;
	}

   section_strtab = (char*)malloc(in_sec.size);
   fseek(f, in_sec.offset, SEEK_SET);
   if (fread(section_strtab, in_sec.size, 1, f) != 1)
		goto error_strtab;
   
   // load sections
   for (int i=1; i < h->sh_num; i++)
   {
      fseek(f, h->sh_off + h->shent_size * i, SEEK_SET);
		if (fread(&in_sec, h->shent_size, 1, f) != 1)
			goto error_strtab;

		// if a section with this name doesn't already exist, add it
      char* name = section_strtab + in_sec.name;

		// make sure this section hasn't already been seen
		if (backend_get_section_by_name(obj, name))
		{
			printf("Warning: duplicate section \"%s\" - skipping\n", name);
		}
		else
		{
         unsigned long flags=0;
			unsigned char* data = NULL;

			// load the section data unless it is marked as unloadable
			if (in_sec.type != SHT_NOBITS)
			{
				data = (unsigned char*)malloc(in_sec.size);

				fseek(f, in_sec.offset, SEEK_SET);
				if (fread(data, in_sec.size, 1, f) != 1)
				{
					fprintf(stderr, "Error loading section %s data\n", name);
					free(data);
					goto error_strtab;
				}
			}

         // set flags for known sections by name
			backend_section_type t;
         if (strcmp(name, ".text") == 0)
            flags = SECTION_FLAG_EXECUTE;
         else if (strcmp(name, ".init") == 0)
            flags = SECTION_FLAG_EXECUTE;
         else if (strcmp(name, ".data") == 0)
            flags = SECTION_FLAG_INIT_DATA;
         else if (strcmp(name, ".rodata") == 0)
            flags = SECTION_FLAG_INIT_DATA;
         else if (strcmp(name, ".bss") == 0)
            flags = SECTION_FLAG_UNINIT_DATA;
         else
         {
            if (in_sec.flags & (1<<SHF_EXECINSTR))
               flags = SECTION_FLAG_EXECUTE;
            if (in_sec.flags & (1<<SHF_ALLOC) && !(in_sec.flags & (1<<SHF_EXECINSTR)) && (!in_sec.flags & (1<<SHF_WRITE)))
               flags = SECTION_FLAG_INIT_DATA;
            if (!(in_sec.flags & SHF_EXECINSTR)) // not exactly accurate - better to set these flags according to section name
               flags = SECTION_FLAG_UNINIT_DATA;
         }

         backend_section *s = backend_add_section(obj, name, in_sec.size, in_sec.addr, data, in_sec.entsize, in_sec.addralign, flags);
			backend_section_set_type(s, elf_to_backend_section_type((section_type)in_sec.type));
      }
   }

   // now that we have the raw data, try to format it as objects the backend can understand (strings, symbols, sections, relocs, etc)

	// find a string table section for looking up symbol names later. There may be more than one, but for now assume there is only one
   sec_strtab = backend_get_section_by_type(obj, SECTION_TYPE_STRTAB);
   if (!sec_strtab)
   {
      printf("Warning: can't find string table section!\n");
      //goto done;
   }

   // create symbols
   sec_symtab = backend_get_section_by_name(obj, ".symtab");
   if (!sec_symtab)
   {
      printf("Warning: can't find symbol table section!\n");
      goto dynsym;
   }

	// Add each symbol to the backend object
   sym = (elf64_symbol*)sec_symtab->data;
   for (int i=0; i < sec_symtab->size/sec_symtab->entry_size; i++, sym++)
	{
		const char* name = NULL;
		backend_section* sec = NULL;
		backend_symbol *s;
		int symbol_flags=0;

		// get the symbol name
		name = (char*)sec_strtab->data + sym->name;
		DEBUG_PRINT("Symbol: %s @ 0x%lx\n", name, sym->value);

		switch (ELF_SYM_TYPE(sym->info))
		{
		case ELF_ST_NOTYPE:
			// The first symbol in an ELF file must have no name and no type
			//printf("Skipping symbol with no type\n");
			if (!backend_add_symbol(obj, name, 0, elf_to_backend_sym_type(sym->info), 0, 0, sec_symtab))
				printf("Failed adding untyped symbol\n");
			continue;

		case ELF_ST_SECTION:
			sec = backend_get_section_by_index(obj, sym->section_index);
			if (!backend_add_symbol(obj, sec->name, 0, elf_to_backend_sym_type(sym->info), 0, 0, sec) || !sec)
				printf("Failed adding section symbol\n");
			//printf("Adding section symbol %s (%i)\n", sec->name, sym->section_index);
			continue;

		case ELF_ST_FILE:
			// set this as the owning file for subsequent symbols
			if (src_file)
				free(src_file);
			if (!name)
			{
				//printf("Found unnamed file symbol\n");
				name = "_global.c";
			}
			//else
			//	printf("Found file symbol %s\n", name);
			src_file = strdup(name);
			break;
		}

		// try to determine the section that this symbol belongs to
		if (sym->section_index <= 0 ||
			sym->section_index == ELF_SECTION_ABS ||
			sym->section_index == ELF_SECTION_COMMON)
		{
			sec = NULL;
		}
		else
		{
			sec = backend_get_section_by_index(obj, sym->section_index);
			//printf("Symbol %s is in section %i (%s)\n", name, sym->section_index, sec->name);
		}

		// set the symbol scope
		if (sym->info & ELF_SYMBOL_GLOBAL)
			symbol_flags |= SYMBOL_FLAG_GLOBAL;

		// add the symbol
		s = backend_add_symbol(obj, name, sym->value, elf_to_backend_sym_type(sym->info), sym->size, symbol_flags, sec);
		if (!s)
		{
			// error adding symbol
		}

		// Some formats contain information relating symbols to the source file
		// that originally defined them. If we have that information, save it in
		// the backend object.
		if (src_file)
		{
			backend_set_source_file(s, src_file);
			//printf("Adding symbol %s to %s\n", name, src_file);
		}
   }

dynsym:
	// Since we are dealing with dynamic symbols, we will need access to the dynamic
	// symbol table, dynamic string table and version tables
   sec_dynamic = backend_get_section_by_name(obj, ".dynamic");
   if (!sec_dynamic)
   {
      printf("Can't find dynamic section!\n");
      goto done;
   }

	// Now find the dynamic string table and symbol table
	dyn_entry = (struct elf64_dyn *)sec_dynamic->data;
	while (dyn_entry->d_tag != DT_NULL)
	{
		switch(dyn_entry->d_tag)
		{
		case DT_STRTAB:
			sec_dynstr = backend_get_section_by_address(obj, dyn_entry->d_ptr);
			if (!sec_dynstr)
			{
				printf("Can't find .dynstr\n");
				goto done;
			}
			printf("Dynamic string table @ 0x%lx (%s)\n", dyn_entry->d_ptr, sec_dynstr->name);
			break;

		case DT_SYMTAB:
			sec_dynsym = backend_get_section_by_address(obj, dyn_entry->d_ptr);
			if (!sec_dynsym)
			{
				printf("Can't find .dynsym\n");
				goto done;
			}
			printf("Dynamic symbol table @ 0x%lx (%s)\n", dyn_entry->d_ptr, sec_dynsym->name);
			break;
		}
		dyn_entry++;
	}

   sec_versymr = backend_get_section_by_name(obj, ".gnu.version_r");
   if (!sec_versymr)
   {
      printf("Can't find .gnu.version_r\n");
      goto done;
   }

   sec_text = backend_get_section_by_name(obj, ".text");
   if (!sec_text)
   {
      printf("Can't find code section!\n");
      goto done;
   }

   // Create dynamic symbols
   // Code is linked using addresses in the PLT section. We want to have a symbol at that address
   // so we can look up by address when disassembling code.

	// find all kinds of interesting facts in the dynamic section
	dyn_entry = (struct elf64_dyn *)sec_dynamic->data;
	while (dyn_entry->d_tag != DT_NULL)
	{
		switch(dyn_entry->d_tag)
		{
		case DT_NEEDED:
			printf("Need library: %s\n", sec_dynstr->data + dyn_entry->d_val);
			break;

		case DT_PLTRELSZ:
			printf("Size of PLT reloc table: %lu\n", dyn_entry->d_val);
			break;

		case DT_PLTGOT:
			sec_got = backend_get_section_by_address(obj, dyn_entry->d_ptr);
			if (!sec_got)
				goto done;
			printf("PLT GOT is in: (%s) %u entries\n",
				sec_got->name, sec_got->size/sec_got->entry_size);
			break;

		case DT_RELA:
			sec_reladyn = backend_get_section_by_address(obj, dyn_entry->d_ptr);
			if (!sec_reladyn)
				goto done;
			printf("Where's the RELA table: 0x%lx (%s)\n", dyn_entry->d_ptr,
				sec_reladyn->name);
			break;

		case DT_RELASZ:
			//DEBUG_PRINT("Size of RELA table: %lu\n", dyn_entry->d_val);
			break;

		case DT_RELAENT:
			//DEBUG_PRINT("Size of RELA entry: %lu\n", dyn_entry->d_val);
			break;

		case DT_PLTREL:
			DEBUG_PRINT("Uses %s table\n", dyn_entry->d_val==DT_REL?"REL":"RELA");
			break;

		case DT_JMPREL:
			sec_relaplt = backend_get_section_by_address(obj, dyn_entry->d_ptr);
			if (!sec_relaplt)
				goto done;
			printf("PLT relocations @ 0x%lx (%s)\n", dyn_entry->d_ptr, sec_relaplt->name);
			break;

		case DT_VERDEF:
		case DT_VERDEFNUM:
		case DT_VERNEED:
		case DT_VERNEEDNUM:
			break;

		// ignore these
		case DT_STRTAB:
		case DT_STRSZ:
		case DT_SYMTAB:
		case DT_SYMENT:
		case DT_INIT:
		case DT_FINI:
		case DT_DEBUG:
		case DT_INIT_ARRAY:
		case DT_FINI_ARRAY:
		case DT_INIT_ARRAYSZ:
		case DT_FINI_ARRAYSZ:
		case DT_FLAGS:
		case DT_ENCODING:
		case DT_PREINIT_ARRAY:
		case DT_PREINIT_ARRAYSZ:
		case DT_MAXPOSTARGS:
			break;

		default:
			printf("Unknown Dynamic tag: %lu\n", dyn_entry->d_tag);
		}
		dyn_entry++;
	}

	// make sure there are dynamic symbol versions. Each entry in the symbol version table
	// corresponds to one entry in the dynamic symbol table (in the same order).

	// Make sure our understanding of the RELA format is correct
	if (sizeof(elf64_rela) != sec_relaplt->entry_size)
	{
		printf("Warning: rela struct size (0x%lx) doesn't match reported size (0x%x)!\n",
			sizeof(elf64_rela), sec_relaplt->entry_size);
	}

	// Each dynamic symbol has a relocation in .rela.plt
	for (rela = (elf64_rela*)sec_relaplt->data; rela < (elf64_rela*)(sec_relaplt->data + sec_relaplt->size); rela++)
   {
		elf64_add_import_from_rela(obj, rela, sec_dynsym, sec_dynstr, sec_versymr);
   }

	// look at .rela.dyn for any missing symbols
	printf("Looking at rela.dyn\n");
	for (rela = (elf64_rela*)sec_reladyn->data; rela < (elf64_rela*)(sec_reladyn->data + sec_reladyn->size); rela++)
   {
		if (ELF64_R_TYPE(rela->info) != R_AMD64_RELATIVE)
		{
			elf64_add_import_from_rela(obj, rela, sec_dynsym, sec_dynstr, sec_versymr);
			printf("Found reladyn for 0x%lx (%u)\n", rela->addr, ELF64_R_TYPE(rela->info));
		}
	}

	DEBUG_PRINT("Adding missing functions from PLT sections\n");
	// Add a normal function symbol for every PLT entry that points to an import symbol
	sec = backend_get_first_section(obj);
	while (sec)
	{
		// we find PLT sections by comparing the first 4 bytes of the name to ".plt" and then checking
		// various flags to increase confidence. I don't know if this is a reliable heuristic or not,
		// but I can't think of an alternative, and it seems to work
		if (memcmp(sec->name, ".plt", 4) == 0 &&
			sec->type == SECTION_TYPE_PROG &&
			sec->flags & (SECTION_FLAG_EXECUTE))
		{
			//DEBUG_PRINT("Found PLT section %s\n", sec->name);

			// iterate over all entries in the PLT
			csh cs_dis;
			cs_insn *cs_ins;
			cs_x86_op *cs_op;
			const uint8_t *pc;
			uint64_t offset;
			uint64_t pc_addr;
			size_t n;
			unsigned int entry_size = sec->entry_size;

			if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_dis) != CS_ERR_OK)
				goto done;
			cs_ins = cs_malloc(cs_dis);

			// There are a few kinds of entries in the PLT. The 'main' PLT is not interesting for us;
			// call instructions use the 'other' PLTs. Since we can't (yet) differentiate, at the top
			// level, we must parse all PLT sections. In x86_64, all entries start with an ENDBR64
			// instruction, which can be used by the processor to validate the jump target. Older code
			// didn't have this feature. The next instruction is how we can differentiate between the
			// entry types. The 'main' PLT entries have a 'push' instruction, while 'other' PLT entries
			// have a jmp instruction into the GOT. We want to create a symbol at this PLT entry because
			// call instructions point to these entries. But to get the symbol name, we must use the
			// GOT entry that the PLT entry is pointing at.
			for (unsigned char *plt_entry = sec->data; plt_entry < (sec->data + sec->size); plt_entry += entry_size)
			{
				// decode the entry
				pc_addr = sec->address + (plt_entry - sec->data);
				pc = plt_entry;
				unsigned long target = decode_plt_entry_x86_64(cs_dis, cs_ins, pc, pc_addr, entry_size);
				if (target)
				{
					backend_symbol* import = backend_find_import_by_address(obj, target);
					if (import)
					{
						DEBUG_PRINT("Adding symbol %s @ 0x%lx size=%u\n", import->name, pc_addr - 0xb, entry_size);
						backend_symbol *pltsym = backend_add_symbol(obj, import->name, pc_addr - 0xb,
							SYMBOL_TYPE_FUNCTION, entry_size, 0, sec_text);
						if (!pltsym)
							printf("Error adding symbol\n");
					}
					else
					{
						printf("Can't find an import symbol for address 0x%lx\n", target);
					}
				}
			}
			cs_close(&cs_dis);
		}
		sec = backend_get_next_section(obj);
	}

done:
   free(section_strtab);

   printf("ELF64 loading done (%i symbols, %i relocs)\n", backend_symbol_count(obj), backend_relocation_count(obj));
   printf("-----------------------------------------\n");
   return obj;

error_strtab:
	free(section_strtab);
error:
	backend_destructor(obj);
	return NULL;
}

static backend_object* elf_read_file(const char* filename)
{
   int fsize;
   elf64_header* h;
   backend_object* obj = NULL;
   char* buff = (char*)malloc(sizeof(elf64_header));

   FILE* f = fopen(filename, "rb");
   if (!f)
   {
      printf("can't open file\n");
      goto done;
   }

   // get size of the file
   fseek(f, 0, SEEK_END);
   fsize = ftell(f);

   // read enough data for the ELF64 header, and then figure out dynamically which one we've got
   fseek(f, 0, SEEK_SET);
	if ((fread(buff, sizeof(elf64_header), 1, f) != 1) ||
		(memcmp(buff, ELF_MAGIC, MAGIC_SIZE) != 0))
	{
		if (config.verbose)
			printf("Error reading elf64 header\n");
      goto done;
	}
   
#ifdef DEBUG
	dump_elf_header(buff);
#endif
   
   h = (elf64_header*)buff;

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

		// Sort the symbols into ELF ordering (null, sections, other locals, globals)
		// This must be done before writing the relocation and symbol tables because
		// they both depend on the ordering. Obviously, no more symbols should be added
		// after calling this function.
		backend_sort_symbols(obj, elfcmp);
   }

   // write file header
   memset(&fh, 0, sizeof(elf32_header));
   memcpy(fh.magic, ELF_MAGIC, MAGIC_SIZE);
   fh.classtype = 1;
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
   char* shstrtab = (char*)malloc(shstrtab_size); // just need enough space for a few strings
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
			unsigned int offset = shstrtab_entry - shstrtab;
			shstrtab_size += 4096;
			printf("Exceeded section header string table size - extending to %u\n", shstrtab_size);
			shstrtab = (char*)realloc(shstrtab, shstrtab_size);
			shstrtab_entry = shstrtab + offset;
      }
      bs = backend_get_next_section(obj);
   }

   // build the symbol string table as well
   char* strtab = (char*)malloc(strtab_size);
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
					unsigned int reloc_type = backend_to_elf32_reloc_type(r->type);
					// elf has 1 null symbol at the beginning that is not accounted for when getting the index
					unsigned int index = backend_get_symbol_index(obj, r->symbol)+1;

					rela.addr = r->offset;
					rela.info = ELF32_R_INFO(index, reloc_type);
					rela.addend = r->addend;
					printf("writing reloc for 0x%x symbol: %s (%u) addend: 0x%x type=%u\n",
						rela.addr, r->symbol->name, index, rela.addend, reloc_type);
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
            fseek(f, sh.offset, SEEK_SET);
      
            // write an empty symbol first
            fwrite(&s, sizeof(elf32_symbol), 1, f);
				sh.info++;

            // now the rest of the symbols
            sym = backend_get_first_symbol(obj);
            while (sym)
            {
               s.name = strtab_entry - strtab;
               s.info = backend_to_elf_sym_type(sym->type);
               s.other = 0;
               s.section_index = ELF_SECTION_UNDEF; // default section
               s.value = sym->val;
               s.size = sym->size;

               if (sym->flags & SYMBOL_FLAG_GLOBAL)
                  s.info |= ELF_SYMBOL_GLOBAL;
					else
						sh.info++;

					// if the symbol points to a section and is not external, set the index
					if (sym->section && !(sym->flags & SYMBOL_FLAG_EXTERNAL))
					{
						//printf("Getting index for section %s for symbol %s\n", sym->section->name, sym->name);
						s.section_index = backend_get_section_index_by_name(obj, sym->section->name);
					}
               if (sym->type == SYMBOL_TYPE_FILE)
                  s.section_index = ELF_SECTION_ABS;

               // if this is an external function, it can't have an address
               if (sym->type == SYMBOL_TYPE_NONE &&
                  sym->flags & (SYMBOL_FLAG_GLOBAL | SYMBOL_FLAG_EXTERNAL))
                  s.value = 0;

					// set the name to point to the string table
               if (sym->name)
               {
                  if (strtab_entry - strtab + strlen(sym->name) > strtab_size)
                  {
                     unsigned int offset = strtab_entry - strtab;
                     strtab_size += 4096;
                     printf("Exceeded string table size - extending to %u\n", strtab_size);
                     strtab = (char*)realloc(strtab, strtab_size);
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
         sh.type = SHT_STRTAB;
         sh.offset = fpos_data;
         sh.size = shstrtab_entry - shstrtab;
			sh.flags = 0;

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

		// Sort the symbols into ELF ordering (null, sections, other locals, globals)
		// This must be done before writing the relocation and symbol tables because
		// they both depend on the ordering. Obviously, no more symbols should be added
		// after calling this function.
		backend_sort_symbols(obj, elfcmp);
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
   char* shstrtab = (char*)malloc(shstrtab_size); // just need enough space for a few strings
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
			unsigned int offset = shstrtab_entry - shstrtab;
			shstrtab_size += 4096;
			printf("Exceeded section header string table size - extending to %u\n", shstrtab_size);
			shstrtab = (char*)realloc(shstrtab, shstrtab_size);
			shstrtab_entry = shstrtab + offset;
      }
      bs = backend_get_next_section(obj);
   }

   // build the symbol string table as well
   char* strtab = (char*)malloc(strtab_size);
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
					unsigned int reloc_type = backend_to_elf64_reloc_type(r->type);
					unsigned int index = backend_get_symbol_index(obj, r->symbol)+1;
					rela.addr = r->offset;
					rela.info = ELF64_R_INFO(index, reloc_type);
					rela.addend = r->addend;
					printf("writing reloc for 0x%lx symbol: %s (%u) addend: 0x%lx type=%u\n",
						rela.addr, r->symbol->name, index, rela.addend, reloc_type);
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
         // sh.info contains the index of the first non-local symbol

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
            fseek(f, sh.offset, SEEK_SET);
      
            // write an empty symbol first
            fwrite(&s, sizeof(elf64_symbol), 1, f);
				sh.info++;

				sym = backend_get_first_symbol(obj);
				while (sym)
				{
					s.name = strtab_entry - strtab;
					s.info = backend_to_elf_sym_type(sym->type);
					s.other = 0;
					s.section_index = ELF_SECTION_UNDEF;
					s.value = sym->val;
					s.size = sym->size;

					if (sym->flags & SYMBOL_FLAG_GLOBAL)
						s.info |= ELF_SYMBOL_GLOBAL;
					else
						sh.info++;

					// if the symbol points to a section and is not external, set the index
					if (sym->section && !(sym->flags & SYMBOL_FLAG_EXTERNAL))
					{
						//printf("Getting index for section %s for symbol %s\n", sym->section->name, sym->name);
						s.section_index = backend_get_section_index_by_name(obj, sym->section->name);
					}
               if (sym->type == SYMBOL_TYPE_FILE)
                  s.section_index = ELF_SECTION_ABS;

               // if this is an external function, it can't have an address
               if (sym->type == SYMBOL_TYPE_NONE &&
                  sym->flags & (SYMBOL_FLAG_GLOBAL | SYMBOL_FLAG_EXTERNAL))
                  s.value = 0;

					// set the name to point to the string table
               if (sym->name)
               {
                  if (strtab_entry - strtab + strlen(sym->name) > strtab_size)
                  {
                     unsigned int offset = strtab_entry - strtab;
                     strtab_size += 4096;
                     //printf("Exceeded string table size - extending to %u\n", strtab_size);
                     strtab = (char*)realloc(strtab, strtab_size);
                     strtab_entry = strtab + offset;
                  }
                  strcpy(strtab_entry, sym->name);
                  strtab_entry += strlen(strtab_entry) + 1;
               }

               fwrite(&s, sizeof(elf64_symbol), 1, f);
					sym = backend_get_next_symbol(obj);
            }

				//printf("First global symbol index %i\n", sh.info);
            fseek(f, fpos_cur, SEEK_SET);
            fpos_data += sh.size;
         }
      }
      else if (strcmp(".strtab", bs->name) == 0)
      {
         // write the .strtab section header
         sh.type = SHT_STRTAB;
         sh.size = strtab_entry - strtab;
			sh.info = 0;
         sh.flags = 0;

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
         sh.type = SHT_STRTAB;
         sh.offset = fpos_data;
         sh.size = shstrtab_entry - shstrtab;
			sh.flags = 0;

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
