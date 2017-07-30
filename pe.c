/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx
MSDOS stub
PE signature
COFF file header
optional header
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "backend.h"

#pragma pack(1)

#define PE_MAGIC "PE\0\0"
#define MAGIC_SIZE 4
#define MAGIC_LOCATOR 0x3C

#define IMAGE_FILE_MACHINE_UNKNOWN 0x0 //The contents of this field are assumed to be applicable to any machine type
#define IMAGE_FILE_MACHINE_AM33 0x1d3 //Matsushita AM33
#define IMAGE_FILE_MACHINE_AMD64 0x8664 //x64
#define IMAGE_FILE_MACHINE_ARM 0x1c0 //ARM little endian
#define IMAGE_FILE_MACHINE_ARM64 0xaa64 //ARM64 little endian
#define IMAGE_FILE_MACHINE_ARMNT 0x1c4 //ARM Thumb-2 little endian
#define IMAGE_FILE_MACHINE_EBC 0xebc //EFI byte code
#define IMAGE_FILE_MACHINE_I386 0x14c //Intel 386 or later processors and compatible processors
#define IMAGE_FILE_MACHINE_IA64 0x200 //Intel Itanium processor family
#define IMAGE_FILE_MACHINE_M32R 0x9041 //Mitsubishi M32R little endian
#define IMAGE_FILE_MACHINE_MIPS16 0x266 //MIPS16
#define IMAGE_FILE_MACHINE_MIPSFPU 0x366 //MIPS with FPU
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x466 //MIPS16 with FPU
#define IMAGE_FILE_MACHINE_POWERPC 0x1f0 //Power PC little endian
#define IMAGE_FILE_MACHINE_POWERPCFP 0x1f1 //Power PC with floating point support
#define IMAGE_FILE_MACHINE_R4000 0x166 //MIPS little endian
#define IMAGE_FILE_MACHINE_RISCV32 0x5032 //RISC-V 32-bit address space
#define IMAGE_FILE_MACHINE_RISCV64 0x5064 //RISC-V 64-bit address space
#define IMAGE_FILE_MACHINE_RISCV128 0x5128 //RISC-V 128-bit address space
#define IMAGE_FILE_MACHINE_SH3 0x1a2 //Hitachi SH3
#define IMAGE_FILE_MACHINE_SH3DSP 0x1a3 //Hitachi SH3 DSP
#define IMAGE_FILE_MACHINE_SH4 0x1a6 //Hitachi SH4
#define IMAGE_FILE_MACHINE_SH5 0x1a8 //Hitachi SH5
#define IMAGE_FILE_MACHINE_THUMB 0x1c2 //Thumb
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x169 //MIPS little-endian WCE v2

#define COFF_FLAG_RELOCS_STRIPPED 0x0001 //Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
#define COFF_FLAG_EXECUTABLE_IMAGE 0x0002 //Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
#define COFF_FLAG_LINE_NUMS_STRIPPED 0x0004 //COFF line numbers have been removed. This flag is deprecated and should be zero.
#define COFF_FLAG_LOCAL_SYMS_STRIPPED 0x0008 //COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
#define COFF_FLAG_AGGRESSIVE_WS_TRIM 0x0010 //Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
#define COFF_FLAG_LARGE_ADDRESS_ AWARE 0x0020 //Application can handle > 2-GB addresses.
//0x0040 This flag is reserved for future use.
#define COFF_FLAG_BYTES_REVERSED_LO 0x0080 //Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
#define COFF_FLAG_32BIT_MACHINE 0x0100 //Machine is based on a 32-bit-word architecture.
#define COFF_FLAG_DEBUG_STRIPPED 0x0200 //Debugging information is removed from the image file.
#define COFF_FLAG_REMOVABLE_RUN_ FROM_SWAP 0x0400 //If the image is on removable media, fully load it and copy it to the swap file.
#define COFF_FLAG_NET_RUN_FROM_SWAP 0x0800 //If the image is on network media, fully load it and copy it to the swap file.
#define COFF_FLAG_SYSTEM 0x1000 //The image file is a system file, not a user program.
#define COFF_FLAG_DLL 0x2000 //The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
#define COFF_FLAG_UP_SYSTEM_ONLY 0x4000 //The file should be run only on a uniprocessor machine.
#define COFF_FLAG_BYTES_REVERSED_HI 0x8000 //Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
typedef struct coff_header
{
   unsigned short machine; // see IMAGE_FILE_MACHINE_
   unsigned short num_sections;
   unsigned int  time_created;
   unsigned int  offset_symtab; // offset to symbol table
   unsigned int  num_symbols;   // number of entries in symbol table
   unsigned short size_optional_hdr;
   unsigned short flags;         // see COFF_FLAGS_
} coff_header;

struct machine_name
{
   unsigned short id;
   char name[31+1];
};

static const struct machine_name machine_lookup[] = 
{
   { IMAGE_FILE_MACHINE_UNKNOWN,    "Unknown machine" },
   { IMAGE_FILE_MACHINE_AM33,       "Matsushita AM33" },
   { IMAGE_FILE_MACHINE_AMD64,      "x64" },
   { IMAGE_FILE_MACHINE_ARM,        "ARM little endian" },
   { IMAGE_FILE_MACHINE_ARM64,      "ARM64 little endian" },
   { IMAGE_FILE_MACHINE_ARMNT,      "ARM Thumb-2 little endian" },
   { IMAGE_FILE_MACHINE_EBC,        "EFI byte code" },
   { IMAGE_FILE_MACHINE_I386,       "Intel 386 or later" },
   { IMAGE_FILE_MACHINE_IA64,       "Intel Itanium" },
   { IMAGE_FILE_MACHINE_M32R,       "Mitsubishi M32R little endian" },
   { IMAGE_FILE_MACHINE_MIPS16,     "MIPS16" },
   { IMAGE_FILE_MACHINE_MIPSFPU,    "MIPS with FPU" },
   { IMAGE_FILE_MACHINE_MIPSFPU16,  "MIPS16 with FPU" },
   { IMAGE_FILE_MACHINE_POWERPC,    "Power PC little endian" },
   { IMAGE_FILE_MACHINE_POWERPCFP,  "Power PC with floating point" },
   { IMAGE_FILE_MACHINE_R4000,      "MIPS little endian" },
   { IMAGE_FILE_MACHINE_RISCV32,    "RISC-V 32-bit address space" },
   { IMAGE_FILE_MACHINE_RISCV64,    "RISC-V 64-bit address space" },
   { IMAGE_FILE_MACHINE_RISCV128,   "RISC-V 128-bit address space" },
   { IMAGE_FILE_MACHINE_SH3,        "Hitachi SH3" },
   { IMAGE_FILE_MACHINE_SH3DSP,     "Hitachi SH3 DSP" },
   { IMAGE_FILE_MACHINE_SH4,        "Hitachi SH4" },
   { IMAGE_FILE_MACHINE_SH5,        "Hitachi SH5" },
   { IMAGE_FILE_MACHINE_THUMB,      "Thumb" },
   { IMAGE_FILE_MACHINE_WCEMIPSV2,  "MIPS little-endian WCE v2" },
};

const char* lookup_machine(unsigned short machine)
{
   for (int i=0; i < sizeof(machine_lookup)/sizeof(struct machine_name); i++)
      if (machine_lookup[i].id == machine)
         return machine_lookup[i].name;
   return machine_lookup[0].name;
}

void dump_coff(coff_header* h)
{
   printf("machine: %s\n", lookup_machine(h->machine));
   printf("num sections: %u\n", h->num_sections);
   time_t creat = h->time_created;
   printf("created: %s\n", ctime(&creat));
   printf("symtab offset: %u\n", h->offset_symtab);
   printf("num symbols: %u\n", h->num_symbols);
   printf("exe header size: %u\n", h->size_optional_hdr);
   printf("flags: 0x%X\n", h->flags);
}

backend_object* coff_read_file(const char* filename)
{
   char buff[sizeof(coff_header)];

   FILE* f = fopen(filename, "rb");
   if (!f)
   {
      printf("can't open file\n");
      return 0;
   }

   // get size of the file
   fseek(f, 0, SEEK_END);
   int fsize = ftell(f);

   if (MAGIC_LOCATOR >= fsize)
      return 0;

   // read location 0x3C to find the offset of the magic number
   fseek(f, MAGIC_LOCATOR, SEEK_SET);
   fread(buff, MAGIC_SIZE, 1, f);
   if (*(unsigned int*)buff >= fsize)
      return 0;

   fseek(f, *(unsigned int*)buff, SEEK_SET);
   fread(buff, MAGIC_SIZE, 1, f);
   if (memcmp(buff, PE_MAGIC, 4) != 0)
      return 0;
   
   printf("found PE magic number\n");
   backend_object* obj = malloc(sizeof(backend_object));
   if (!obj)
      return 0;
   backend_set_type(obj, OBJECT_TYPE_PE32);
   // read the coff header
   fread(buff, sizeof(coff_header), 1, f);
   coff_header* h = (coff_header*)buff;
   dump_coff(h);
   return obj;
}

backend_ops coff =
{
   .read = coff_read_file
};

void pe_init(void)
{
   backend_register(&coff);
}
