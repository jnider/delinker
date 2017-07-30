/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx
MSDOS stub
PE signature
COFF file header
optional header
*/

#include <stdio.h>
#include <string.h>
#include "backend.h"

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
   unsigned long  time_created;
   unsigned long  offset_symtab; // offset to symbol table
   unsigned long  num_symbols;   // number of entries in symbol table
   unsigned short size_optional_hdr;
   unsigned short flags;         // see COFF_FLAGS_
} coff_header;

backend_object* coff_read_file(const char* filename)
{
   printf("coff_read_file\n");
   char buff[MAGIC_SIZE];

   FILE* f = fopen(filename, "rb");
   if (!f)
   {
      printf("can't open file\n");
      return 0;
   }

   //int size = sizeof(coff_header) + sizeof(pe_header);
   //printf("Reading %i bytes\n", size);
   //fread(buff, size, 1, f);

   //pe_header* pe = (pe_header*)buff;
   //if (memcmp(pe->pe_magic, PE_MAGIC, 4) == 0)
   //   printf("found PE magic number\n");

   // get size of the file
   fseek(f, 0, SEEK_END);
   int fsize = ftell(f);

   if (MAGIC_LOCATOR >= fsize)
      return 0;

   // read location 0x3C to find the offset of the magic number
   fseek(f, MAGIC_LOCATOR, SEEK_SET);
   fread(buff, MAGIC_SIZE, 1, f);
   printf("magic at offset=0x%x\n", *(unsigned int*)buff);
   if (*(unsigned int*)buff >= fsize)
      return 0;

   fseek(f, *(unsigned int*)buff, SEEK_SET);
   fread(buff, MAGIC_SIZE, 1, f);
   if (memcmp(buff, PE_MAGIC, 4) == 0)
      printf("found PE magic number\n");
   return 0;
}

backend_ops coff =
{
   .read = coff_read_file
};

void pe_init(void)
{
   printf("pe_init ops=0x%x\n", &coff);
   backend_register(&coff);
}
