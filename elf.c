/* https://en.wikipedia.org/wiki/Executable_and_Linkable_Format */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "backend.h"

#pragma pack(1)

#define ELF_MAGIC "\x7F\x45\x4c\x46"
#define MAGIC_SIZE 4

#define ELF_ISA_UNSPECIFIED 0
#define ELF_ISA_SPARC 2
#define ELF_ISA_X86 3
#define ELF_ISA_MIPS 8
#define ELF_ISA_POWERPC 0x14
#define ELF_ISA_S390 0x16
#define ELF_ISA_ARM 0x28
#define ELF_ISA_SUPERH 0x2A
#define ELF_ISA_IA64 0x32
#define ELF_ISA_X86_64 0x3E
#define ELF_ISA_AARCH64 0xB7
#define ELF_ISA_RISCV 0xF3

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
	ELF_OS_SORTIX = 0x53
} os;

typedef enum type
{
	ELF_TYPE_RELOC,
	ELF_TYPE_EXEC,
	ELF_TYPE_SHARED,
	ELF_TYPE_CORE
} type;

// Machines

// Flags

// the symbol classes

// section flags

typedef struct elf64_header
{
	char magic[4];
	char size; 			// 1=32 bit, 2=64 bit
	char endian;		// 1=little, 2=big
	char version;
	char os;				// see ELF_OS_
	char abi;
	char padding[7];
	short type;			// see ELF_TYPE_
} elf64_header;

struct machine_name
{
   unsigned short id;
   char name[31+1];
};

static const struct machine_name machine_lookup[] = 
{
   { ELF_ISA_UNSPECIFIED,    "Unknown machine" },
   { ELF_ISA_SPARC,    "SPARC" },
   { ELF_ISA_X86,    "x86" },
   { ELF_ISA_MIPS,    "MIPS" },
   { ELF_ISA_POWERPC,    "PowerPC" },
   { ELF_ISA_S390,    "S390" },
   { ELF_ISA_ARM,    "ARM" },
   { ELF_ISA_SUPERH,    "SuperH" },
   { ELF_ISA_IA64,    "IA 64" },
   { ELF_ISA_X86_64,    "x86-64" },
   { ELF_ISA_AARCH64,    "AArch64" },
   { ELF_ISA_RISCV,    "RISC-V" },
};

static const char* flags_lookup[] = 
{
   "Does not contain base relocations and must therefore be loaded at its preferred base address",
};

static const char* subsystem_lookup[] = 
{
   "An unknown subsystem",
};

static const char* section_flags_lookup[] = 
{
   "",
};

static const char* elf_lookup_machine(unsigned short machine)
{
   for (int i=0; i < sizeof(machine_lookup)/sizeof(struct machine_name); i++)
      if (machine_lookup[i].id == machine)
         return machine_lookup[i].name;
   return machine_lookup[0].name;
}

/*
void dump_symtab(symbol* symtab, unsigned int count, char* stringtab)
{
}

static void dump_sections(section_header* secs, unsigned int nsec)
{
   for (unsigned int i=0; i < nsec; i++)
   {
      printf("Index: %i\n", i+1);
      printf("Section Name: %s\n", secs[i].name);
      printf("Size in mem: %u\n", secs[i].size_in_mem);
      printf("Address: 0x%x\n", secs[i].address);
      printf("Data ptr: %u\n", secs[i].data_offset); 
      printf("Flags: 0x%x\n", secs[i].flags);
      for (int f=0; f < 19; f++)
         if (secs[i].flags & (1<<f))
            printf("   - %s\n", section_flags_lookup[f]);
      for (int f=24; f < 31; f++)
         if (secs[i].flags & (1<<f))
            printf("   - %s\n", section_flags_lookup[f]);
      printf("Alignment: %i\n", (secs[i].flags & SCN_ALIGN_MASK)>>SCN_ALIGN);
   }
}
*/

/* identifies the file format we can write */
backend_type elf64_format(void)
{
   return OBJECT_TYPE_ELF64;
}

static backend_object* elf64_read_file(const char* filename)
{
   char* buff = malloc(sizeof(elf64_header));

   FILE* f = fopen(filename, "rb");
   if (!f)
   {
      printf("can't open file\n");
      free(buff);
      return 0;
   }

	printf("elf64_read_file\n");
   // get size of the file
   fseek(f, 0, SEEK_END);
   int fsize = ftell(f);

   // read enough data for the ELF64 header, and then figure out dynamically which one we've got
   fseek(f, 0, SEEK_SET);
   fread(buff, sizeof(elf64_header), 1, f);
   if (memcmp(buff, ELF_MAGIC, MAGIC_SIZE) != 0)
   {
      free(buff);
      return 0;
   }
   
   printf("found ELF magic number\n");
   
   backend_object* obj = backend_create();
   if (!obj)
   {
      free(buff);
      return 0;
   }

   return obj;
}

static int elf64_write_file(backend_object* obj, const char* filename)
{
   FILE* f = fopen(filename, "wb");
   if (!f)
   {
      printf("can't open file\n");
      return -1;
   }

   // write file header

   fclose(f);
   return 0;
}

backend_ops elf64_backend =
{
   .format = elf64_format,
   .read = elf64_read_file,
   .write = elf64_write_file
};

void elf_init(void)
{
   backend_register(&elf64_backend);
}
