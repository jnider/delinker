/* General layout: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format */
/* 32-bit layout: http://www.cs.cmu.edu/afs/cs/academic/class/15213-s00/doc/elf.pdf */
/* 64-bit layout: https://www.uclibc.org/docs/elf-64-gen.pdf */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "backend.h"

#pragma pack(1)

#define ELF_MAGIC "\x7F\x45\x4c\x46"
#define MAGIC_SIZE 4

#define ELF_SECTION_ABS 0xFFF1
#define ELF_SECTION_COMMON 0xFFF2

typedef enum elf_machine
{
	ELF_ISA_UNSPECIFIED,
	ELF_ISA_M32,			// AT&T WE 32100
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

// Flags

// section flags

typedef struct elf32_header
{
	char magic[4];
	char size; 			// 1=32 bit, 2=64 bit
	char endian;		// 1=little, 2=big
	char h_version;
	char os;				// see ELF_OS_
	char abi;
	char padding[7];
	short type;			// see ELF_TYPE_
	short machine;		// see ELF_MACHINE_
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
	char size; 			// 1=32 bit, 2=64 bit
	char endian;		// 1=little, 2=big
	char h_version;
	char os;				// see ELF_OS_
	char abi;
	char padding[7];
	short type;			// see ELF_TYPE_
	short machine;		// see ELF_MACHINE_
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

struct item_name
{
   unsigned short id;
   char name[31+1];
};

static const struct item_name machine_lookup[] = 
{
   { ELF_ISA_UNSPECIFIED,    "Unknown machine" },
	{ ELF_ISA_M32, 		"AT&T WE 32100" },
   { ELF_ISA_SPARC,    "SPARC" },
   { ELF_ISA_X86,    "x86" },
	{ ELF_ISA_68K, 	"Motorola 68000" },
	{ ELF_ISA_88K, 	"Motorola 88000" },
	{ ELF_ISA_860, 	"Intel 80860" },
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

const char* elf64_name(void)
{
	return "elf64";
}

/* identifies the file format we can read/write */
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
	backend_section* sec_bss = NULL;
	backend_section* sec_data = NULL;
	backend_section* sec_interp = NULL;
	backend_section* sec_rodata = NULL;
	backend_section* sec_text = NULL;
	backend_section* sec_got = NULL;

   backend_object* obj = backend_create();
   if (!obj)
      return 0;

	backend_set_type(obj, OBJECT_TYPE_ELF64);

	printf("Number of section headers: %i\n", h->sh_num); 
	printf("Size of section headers: %i\n", h->shent_size); 
	printf("String table index: %i\n", h->sh_str_index);

	// build a little lookup table relating ELF section numbers to backend section pointers
	// the ELF section number is a direct index into the table, which assumes the section numbers
	// are sequential starting from 0 (which according to the spec they are, but who knows).
	backend_section** sec_lut = calloc(h->sh_num, sizeof(backend_section*));

	elf64_section* s = malloc(sizeof(elf64_section)); // this could be on the stack

	// first, preload the section header string table
   fseek(f, h->sh_off + h->shent_size * h->sh_str_index, SEEK_SET);
   fread(s, h->shent_size, 1, f);

	char* section_strtab = malloc(s->size);
	fseek(f, s->offset, SEEK_SET);
	fread(section_strtab, s->size, 1, f);
	
	printf("ELF64: Adding sections\n");
	// add the usual suspects
	int index;
	index = elf64_find_section(f, h, ".bss", section_strtab, s);
	if (index >= 0)
	{
		unsigned long flags;
		char* data = malloc(s->size);
		fseek(f, s->offset, SEEK_SET);
		fread(data, s->size, 1, f);
		flags = 1<<SECTION_FLAG_UNINIT_DATA;
		sec_bss = backend_add_section(obj, 0, ".bss", s->size, s->addr, data, s->addralign, flags);
		sec_lut[index] = sec_bss;
		free(data);
	}

	index = elf64_find_section(f, h, ".data", section_strtab, s);
	if (index >= 0)
	{
		unsigned long flags;
		char* data = malloc(s->size);
		fseek(f, s->offset, SEEK_SET);
		fread(data, s->size, 1, f);
		flags = 1<<SECTION_FLAG_INIT_DATA;
		sec_data = backend_add_section(obj, 0, ".data", s->size, s->addr, data, s->addralign, flags);
		sec_lut[index] = sec_data;
		free(data);
	}

	index = elf64_find_section(f, h, ".interp", section_strtab, s);
	if (index >= 0)
	{
		unsigned long flags;
		char* data = malloc(s->size);
		fseek(f, s->offset, SEEK_SET);
		fread(data, s->size, 1, f);
		flags = 0;
		sec_interp = backend_add_section(obj, 0, ".interp", s->size, s->addr, data, s->addralign, flags);
		sec_lut[index] = sec_interp;
		free(data);
	}

	index = elf64_find_section(f, h, ".rodata", section_strtab, s);
	if (index >= 0)
	{
		unsigned long flags;
		char* data = malloc(s->size);
		fseek(f, s->offset, SEEK_SET);
		fread(data, s->size, 1, f);
		flags = 1<<SECTION_FLAG_INIT_DATA;
		sec_rodata = backend_add_section(obj, 0, ".rodata", s->size, s->addr, data, s->addralign, flags);
		sec_lut[index] = sec_rodata;
		free(data);
	}

	index = elf64_find_section(f, h, ".text", section_strtab, s);
	if (index >= 0)
	{
		unsigned long flags;
		char* data = malloc(s->size);
		fseek(f, s->offset, SEEK_SET);
		fread(data, s->size, 1, f);
		flags = 1<<SECTION_FLAG_CODE;
		sec_text = backend_add_section(obj, 0, ".text", s->size, s->addr, data, s->addralign, flags);
		sec_lut[index] = sec_text;
		free(data);
	}

	index = elf64_find_section(f, h, ".got", section_strtab, s);
	if (index >= 0)
	{
		unsigned long flags;
		char* data = malloc(s->size);
		fseek(f, s->offset, SEEK_SET);
		fread(data, s->size, 1, f);
		flags = 0;
		sec_got = backend_add_section(obj, 0, ".got", s->size, s->addr, data, s->addralign, flags);
		sec_lut[index] = sec_got;
		free(data);
	}

	// find and load the symbol string table
	char* sym_strtab = NULL;
	if (elf64_find_section(f, h, ".strtab", section_strtab, s) < 0)
	{
		printf("Warning: can't find string table\n");
		goto done;
	}

	sym_strtab = malloc(s->size);
	fseek(f, s->offset, SEEK_SET);
	fread(sym_strtab, s->size, 1, f);

	// load and add the symbols separately
	if (elf64_find_section(f, h, ".symtab", section_strtab, s) < 0)
	{
		printf("Warning: can't find symbol table\n");
		goto done;
	}
	
	elf64_symbol* symtab = malloc(s->size);
	fseek(f, s->offset, SEEK_SET);
	fread(symtab, s->size, 1, f);

	//printf("Symbol size: %lu vs %lu\n", s->entsize, sizeof(elf64_symbol));
	elf64_symbol* sym = NULL;
	for (int i=0; i < s->size/s->entsize; i++)
	{
		sym = &symtab[i];
		if (symtab[i].name)
		{	
			backend_section* sec;
			char* name = sym_strtab + sym->name;

			// try to determine the section that this symbol belongs to
			if (sym->section_index < 0 || sym->section_index == ELF_SECTION_ABS || sym->section_index == ELF_SECTION_COMMON)
				sec = NULL;
			else
				sec = sec_lut[sym->section_index];

			backend_add_symbol(obj, name, sym->value, elf_to_backend_sym_type(sym->info), 0, sec);
		}
	}
	free(symtab);

done:
	free(s);
	free(section_strtab);
	free(sym_strtab);
	free(sec_lut);

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

static int elf64_write_file(backend_object* obj, const char* filename)
{
	backend_section *bs;
	elf64_header fh;
	elf64_section sh;

	//printf("elf64_write_file\n");

   FILE* f = fopen(filename, "wb");
   if (!f)
   {
      printf("can't open file\n");
      return -1;
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
	fh.sh_num = 8; // the regulars: NULL, .text, .data, .rodata, .bss, .symtab, .strtab, .shstrtab
	fh.sh_str_index = 7;
	// may also need .rela.text 
	//printf("write header\n");
   fwrite(&fh, sizeof(elf64_header), 1, f);

	// so we know where to write the next object
	int fpos_cur;
	int fpos_data = fh.sh_off + fh.shent_size*fh.sh_num;

	// build the section header string table with the names we need
	char* shstrtab = malloc(1000); // just need enough space for a few strings
	char* strtab_entry = shstrtab+1;
	shstrtab[0] = 0; // the initial entry is always 0

	// write the null section header
	//printf("write null section header\n");
	memset(&sh, 0, sizeof(elf64_section));
   fwrite(&sh, sizeof(elf64_section), 1, f);

	// write the .text section & header
	//printf("write .text section\n");
	sh.name = strtab_entry - shstrtab;
	sh.type = SHT_PROGBITS;
	sh.flags = (1<<SHF_ALLOC) | (1<<SHF_EXECINSTR);
	sh.addr = 0;
	sh.size = 0;
	sh.addralign = 0;

	bs = backend_get_section_by_name(obj, ".text");
	if (bs)
	{
		sh.addr = bs->address;
		sh.size = bs->size;
		sh.addralign = bs->alignment;
		//printf("Using .text alignment= %i\n", sh.addralign);
	}

	// write the data if there is any
	if (sh.size)
	{
		//printf("Writing data %i\n", sh.size);
		sh.offset = fpos_data;
		fpos_cur = ftell(f);
		fseek(f, sh.offset, SEEK_SET);
		fwrite(bs->data, sh.size, 1, f);
		fseek(f, fpos_cur, SEEK_SET);
		fpos_data += sh.size;
	}
	strcpy(strtab_entry, ".text");
	strtab_entry += strlen(strtab_entry) + 1;
   fwrite(&sh, sizeof(elf64_section), 1, f);

	// write the .data section header
	//printf("write .data section\n");
	sh.name = strtab_entry - shstrtab;
	sh.type = SHT_PROGBITS;
	sh.flags = (1<<SHF_ALLOC) | (1<<SHF_WRITE);
	sh.offset = 0;
	sh.link = 0;
	sh.info = 0;
	sh.entsize = 0;
	sh.addr = 0;
	sh.size = 0;
	sh.addralign = 0;
	bs = backend_get_section_by_name(obj, ".data");
	if (bs)
	{
		sh.addr = bs->address;
		sh.size = bs->size;
		sh.addralign = bs->alignment;
	}

	// write the data if there is any
	if (sh.size)
	{
		sh.offset = fpos_data;
		fpos_cur = ftell(f);
		fseek(f, sh.offset, SEEK_SET);
		fwrite(bs->data, sh.size, 1, f);
		fseek(f, fpos_cur, SEEK_SET);
		fpos_data += sh.size;
	}
	strcpy(strtab_entry, ".data");
	strtab_entry += strlen(strtab_entry) + 1;
   fwrite(&sh, sizeof(elf64_section), 1, f);

	// write the .bss section header
	//printf("write .bss section\n");
	sh.name = strtab_entry - shstrtab;
	sh.type = SHT_NOBITS;
	sh.flags = (1<<SHF_ALLOC) | (1<<SHF_WRITE);
	sh.offset = 0;
	sh.link = 0;
	sh.info = 0;
	sh.entsize = 0;
	sh.addr = 0;
	sh.size = 0;
	sh.addralign = 0;
	bs = backend_get_section_by_name(obj, ".bss");
	if (bs)
	{
		sh.addr = bs->address;
		sh.size = bs->size;
		sh.addralign = bs->alignment;
	}

	// write the data if there is any
	if (sh.size)
	{
		sh.offset = fpos_data;
		fpos_cur = ftell(f);
		fseek(f, sh.offset, SEEK_SET);
		fwrite(bs->data, sh.size, 1, f);
		fseek(f, fpos_cur, SEEK_SET);
		fpos_data += sh.size;
	}
	strcpy(strtab_entry, ".bss");
	strtab_entry += strlen(strtab_entry) + 1;
   fwrite(&sh, sizeof(elf64_section), 1, f);

	// write the .rodata section header
	sh.name = strtab_entry - shstrtab;
	sh.type = SHT_PROGBITS;
	sh.flags = (1<<SHF_ALLOC);
	sh.offset = 0;
	sh.link = 0;
	sh.info = 0;
	sh.entsize = 0;
	sh.addr = 0;
	sh.size = 0;
	sh.addralign = 0;
	bs = backend_get_section_by_name(obj, ".rodata");
	if (bs)
	{
		sh.addr = bs->address;
		sh.size = bs->size;
		sh.addralign = bs->alignment;
	}

	// write the data if there is any
	if (sh.size)
	{
		sh.offset = fpos_data;
		fpos_cur = ftell(f);
		fseek(f, sh.offset, SEEK_SET);
		fwrite(bs->data, sh.size, 1, f);
		fseek(f, fpos_cur, SEEK_SET);
		fpos_data += sh.size;
	}
	strcpy(strtab_entry, ".rodata");
	strtab_entry += strlen(strtab_entry) + 1;
   fwrite(&sh, sizeof(elf64_section), 1, f);

	// write the .symtab section header
	sh.name = strtab_entry - shstrtab;
	sh.type = SHT_SYMTAB;
	sh.flags = 0;
	sh.offset = 0;
	sh.link = 0;
	sh.info = 0;
	sh.entsize = sizeof(elf64_symbol);
	sh.addr = 0;
	sh.size = 0;
	sh.addralign = 8;
	bs = backend_get_section_by_name(obj, ".symtab");
	if (bs)
	{
		sh.size = bs->size;
		sh.addr = bs->address;
		sh.addralign = bs->alignment;
	}

	// write the data if there is any
	if (sh.size)
	{
		sh.offset = fpos_data;
		fpos_cur = ftell(f);
		fseek(f, sh.offset, SEEK_SET);
		fwrite(bs->data, sh.size, 1, f);
		fseek(f, fpos_cur, SEEK_SET);
		fpos_data += sh.size;
	}
	strcpy(strtab_entry, ".symtab");
	strtab_entry += strlen(strtab_entry) + 1;
   fwrite(&sh, sizeof(elf64_section), 1, f);

	// write the .strtab section header
	sh.name = strtab_entry - shstrtab;
	strcpy(strtab_entry, ".strtab");
	strtab_entry += strlen(strtab_entry) + 1;
	sh.type = SHT_STRTAB;
	sh.flags = 0;
	sh.offset = 0;
	sh.link = 0;
	sh.info = 0;
	sh.entsize = 0;
	sh.addr = 0;
	sh.size = 0;
	sh.addralign = 1;
	bs = backend_get_section_by_name(obj, ".strtab");
	if (bs)
	{
		sh.addr = bs->address;
		sh.size = bs->size;
		sh.addralign = bs->alignment;
	}

	//printf("STRTAB entry: %s\n", sh.name + shstrtab);
	// write the data if there is any
	if (sh.size)
	{
		sh.offset = fpos_data;
		fpos_cur = ftell(f);
		fseek(f, sh.offset, SEEK_SET);
		fwrite(bs->data, sh.size, 1, f);
		fseek(f, fpos_cur, SEEK_SET);
		fpos_data += sh.size;
	}
   fwrite(&sh, sizeof(elf64_section), 1, f);

	// write the .shstrtab section header
	strcpy(strtab_entry, ".shstrtab");
	sh.name = strtab_entry - shstrtab;
	strtab_entry += strlen(strtab_entry) + 1;

	sh.type = SHT_STRTAB;
	sh.flags = 0;
	sh.offset = fpos_data;
	sh.link = 0;
	sh.info = 0;
	sh.entsize = 0;
	sh.addr = 0;
	sh.size = strtab_entry - shstrtab;
	sh.addralign = 1;

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
   fwrite(&sh, sizeof(elf64_section), 1, f);

done:
   fclose(f);
   return 0;
}

backend_ops elf64_backend =
{
	.name = elf64_name,
   .format = elf64_format,
   .read = elf_read_file,
   .write = elf64_write_file
};

void elf_init(void)
{
   backend_register(&elf64_backend);
}
