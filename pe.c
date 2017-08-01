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
#define STATE_ID_NORMAL 0x10B
#define STATE_ID_ROM 0x107
#define STATE_ID_PE32PLUS 0x20B

#define IMAGE_FILE_MACHINE_UNKNOWN     0x0 //The contents of this field are assumed to be applicable to any machine type
#define IMAGE_FILE_MACHINE_AM33        0x1d3 //Matsushita AM33
#define IMAGE_FILE_MACHINE_AMD64       0x8664 //x64
#define IMAGE_FILE_MACHINE_ARM         0x1c0 //ARM little endian
#define IMAGE_FILE_MACHINE_ARM64       0xaa64 //ARM64 little endian
#define IMAGE_FILE_MACHINE_ARMNT       0x1c4 //ARM Thumb-2 little endian
#define IMAGE_FILE_MACHINE_EBC         0xebc //EFI byte code
#define IMAGE_FILE_MACHINE_I386        0x14c //Intel 386 or later processors and compatible processors
#define IMAGE_FILE_MACHINE_IA64        0x200 //Intel Itanium processor family
#define IMAGE_FILE_MACHINE_M32R        0x9041 //Mitsubishi M32R little endian
#define IMAGE_FILE_MACHINE_MIPS16      0x266 //MIPS16
#define IMAGE_FILE_MACHINE_MIPSFPU     0x366 //MIPS with FPU
#define IMAGE_FILE_MACHINE_MIPSFPU16   0x466 //MIPS16 with FPU
#define IMAGE_FILE_MACHINE_POWERPC     0x1f0 //Power PC little endian
#define IMAGE_FILE_MACHINE_POWERPCFP   0x1f1 //Power PC with floating point support
#define IMAGE_FILE_MACHINE_R4000       0x166 //MIPS little endian
#define IMAGE_FILE_MACHINE_RISCV32     0x5032 //RISC-V 32-bit address space
#define IMAGE_FILE_MACHINE_RISCV64     0x5064 //RISC-V 64-bit address space
#define IMAGE_FILE_MACHINE_RISCV128    0x5128 //RISC-V 128-bit address space
#define IMAGE_FILE_MACHINE_SH3         0x1a2 //Hitachi SH3
#define IMAGE_FILE_MACHINE_SH3DSP      0x1a3 //Hitachi SH3 DSP
#define IMAGE_FILE_MACHINE_SH4         0x1a6 //Hitachi SH4
#define IMAGE_FILE_MACHINE_SH5         0x1a8 //Hitachi SH5
#define IMAGE_FILE_MACHINE_THUMB       0x1c2 //Thumb
#define IMAGE_FILE_MACHINE_WCEMIPSV2   0x169 //MIPS little-endian WCE v2

// Flags
#define COFF_FLAG_RELOCS_STRIPPED      0x0001 //Does not contain base relocations and must therefore be loaded at its preferred base address
#define COFF_FLAG_SHIFT_RELOCS_STRIPPED 0
#define COFF_FLAG_EXECUTABLE_IMAGE     0x0002 //The image file is valid and can be run
#define COFF_FLAG_SHIFT_EXECUTABLE_IMAGE 1
#define COFF_FLAG_LINE_NUMS_STRIPPED   0x0004 //COFF line numbers have been removed
#define COFF_FLAG_SHIFT_LINE_NUMS_STRIPPED 2
#define COFF_FLAG_LOCAL_SYMS_STRIPPED  0x0008 //COFF symbol table entries for local symbols have been removed
#define COFF_FLAG_SHIFT_LOCAL_SYMS_STRIPPED 3
#define COFF_FLAG_AGGRESSIVE_WS_TRIM   0x0010 //Obsolete. Aggressively trim working set
#define COFF_FLAG_SHIFT_AGGRESSIVE_WS_TRIM 4
#define COFF_FLAG_LARGE_ADDRESS_AWARE  0x0020 //Application can handle > 2-GB addresses.
#define COFF_FLAG_SHIFT_LARGE_ADDRESS 5
                                    //0x0040 This flag is reserved for future use.
#define COFF_FLAG_BYTES_REVERSED_LO    0x0080 //Little endian
#define COFF_FLAG_SHIFT_BYTES_REVERSED_LO 7
#define COFF_FLAG_32BIT_MACHINE        0x0100 //Machine is based on a 32-bit-word architecture.
#define COFF_FLAG_SHIFT_32BIT_MACHINE 8
#define COFF_FLAG_DEBUG_STRIPPED       0x0200 //Debugging information is removed from the image file.
#define COFF_FLAG_SHIFT_DEBUG_STRIPPED 9
#define COFF_FLAG_REMOVABLE_RUN_FROM_SWAP 0x0400 //If the image is on removable media, fully load it and copy it to the swap file.
#define COFF_FLAG_SHIFT_REMOVABLE_RUN_FROM_SWAP 10
#define COFF_FLAG_NET_RUN_FROM_SWAP    0x0800 //If the image is on network media, fully load it and copy it to the swap file.
#define COFF_FLAG_SHIFT_NET_RUN_FROM_SWAP 11
#define COFF_FLAG_SYSTEM               0x1000 //The image file is a system file, not a user program.
#define COFF_FLAG_SHIFT_SYSTEM 12
#define COFF_FLAG_DLL                  0x2000 //The image file is a dynamic-link library (DLL)
#define COFF_FLAG_SHIFT_DLL 13
#define COFF_FLAG_UP_SYSTEM_ONLY       0x4000 //The file should be run only on a uniprocessor machine.
#define COFF_FLAG_SHIFT_UP_SYSTEM_ONLY 14
#define COFF_FLAG_BYTES_REVERSED_HI    0x8000 //Big endian
#define COFF_FLAG_SHIFT_BYTES_REVERSED_HI 15

// the symbol classes
#define SYM_CLASS_EXTERNAL 2
#define SYM_CLASS_STATIC 3 // The offset of the symbol within the section. If the Value field is zero, then the symbol represents a section name.
#define SYM_CLASS_FUNCTION 101
#define SYM_CLASS_FILE 103
#define SYM_CLASS_SECTION 104

typedef enum subsystem
{
   IMAGE_SUBSYSTEM_UNKNOWN, //0 An unknown subsystem
   IMAGE_SUBSYSTEM_NATIVE,       //1 Device drivers and native Windows processes
   IMAGE_SUBSYSTEM_WINDOWS_GUI,  //2 The Windows graphical user interface (GUI) subsystem
   IMAGE_SUBSYSTEM_WINDOWS_CUI,  //3 The Windows character subsystem
   IMAGE_SUBSYSTEM_4,
   IMAGE_SUBSYSTEM_OS2_CUI,      //5 The OS/2 character subsystem
   IMAGE_SUBSYSTEM_6,
   IMAGE_SUBSYSTEM_POSIX_CUI,    //7 The Posix character subsystem
   IMAGE_SUBSYSTEM_NATIVE_WINDOWS, //8 Native Win9x driver
   IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, //9 Windows CE
   IMAGE_SUBSYSTEM_EFI_APPLICATION, //10 An Extensible Firmware Interface (EFI) application
   IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER, //11 An EFI driver with boot services
   IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, //12 An EFI driver with run-time services
   IMAGE_SUBSYSTEM_EFI_ROM, //13 An EFI ROM image
   IMAGE_SUBSYSTEM_XBOX, //14 XBOX
   IMAGE_SUBSYSTEM_15, //15 unknown
   IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION, //16 Windows boot application.
   IMAGE_SUBSYSTEM_MAX
} subsystem;

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

typedef struct optional_header
{
   unsigned char major_linker_ver;
   unsigned char minor_linker_ver;
   unsigned int code_size;
   unsigned int data_size;
   unsigned int uninit_data_size;
   unsigned int entry;
   unsigned int code_base;
   unsigned int data_base;
} optional_header;

typedef struct pe32_windows_header
{
   unsigned int base;
   unsigned int section_alignment;
   unsigned int file_alignment;
   unsigned short os_major;
   unsigned short os_minor;
   unsigned short image_major;
   unsigned short image_minor;
   unsigned short subsys_major;
   unsigned short subsys_minor;
   unsigned int win32ver;
   unsigned int image_size;
   unsigned int header_size;
   unsigned int checksum;
   unsigned short subsystem; // see IMAGE_SUBSYSTEM_
   unsigned short dll_chars;
   unsigned int stack_size;
   unsigned int stack_commit_size;
   unsigned int heap_size;
   unsigned int heap_commit_size;
   unsigned int loader_flags;
   unsigned int num_rva;
} pe32_windows_header;

typedef struct section_header
{
   char name[8];
   unsigned int size_in_mem;
   unsigned int address;
   unsigned int size_on_disk;
   unsigned int data_offset;
   unsigned int reloc;
   unsigned int linenums;
   unsigned short num_reloc;
   unsigned short num_lines; 
   unsigned int flags;
} section_header;

typedef struct data_dir
{
   unsigned int address;
   unsigned int size;
} data_dir;

typedef struct data_dirs
{
   data_dir export;
   data_dir import;
   data_dir resource;
   data_dir exception;
   data_dir certificate;
   data_dir relocation;
   data_dir debug;
   data_dir arch;
   data_dir ptr;
   data_dir tls;
   data_dir load;
   data_dir bound;
   data_dir iat;
   data_dir delay;
   data_dir clr;
   data_dir reserved;
} data_dirs;

typedef struct symbol
{
   union
   {
      char str[8];
      struct
      {
         unsigned int zeros;
         unsigned int index;
      } ptr;
   } name;
   unsigned int val;
   short section; // index, 0=external, -1=abs, -2=debugging (file)
   unsigned short type; // LSB: base type MSB: complex type
   unsigned char class;
   unsigned char auxsymbols;
} symbol;

struct machine_name
{
   unsigned short id;
   char name[31+1];
};

static const struct machine_name machine_lookup[] = 
{
   { IMAGE_FILE_MACHINE_UNKNOWN,    "Unknown machine" },

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

static const char* flags_lookup[] = 
{
   "Does not contain base relocations and must therefore be loaded at its preferred base address",
   "The image file is valid and can be run",
   "COFF line numbers have been removed",
   "COFF symbol table entries for local symbols have been removed",
   "Obsolete. Aggressively trim working set",
   "Application can handle > 2-GB addresses",
   "RESERVED",
   "Little endian",
   "Machine is based on a 32-bit-word architecture",
   "Debugging information is removed from the image file.",
   "If the image is on removable media, fully load it and copy it to the swap file",
   "If the image is on network media, fully load it and copy it to the swap file",
   "The image file is a system file, not a user program",
   "The image file is a dynamic-link library (DLL)",
   "The file should be run only on a uniprocessor machine",
   "Big endian"
};

static const char* subsystem_lookup[] = 
{
   "An unknown subsystem",
   "Device drivers and native Windows processes",
   "The Windows graphical user interface (GUI) subsystem",
   "The Windows character subsystem",
   "IMAGE_SUBSYSTEM_4",
   "The OS/2 character subsystem",
   "IMAGE_SUBSYSTEM_6",
   "The Posix character subsystem",
   "Native Win9x driver",
   "Windows CE",
   "An Extensible Firmware Interface (EFI) application",
   "An EFI driver with boot services",
   "An EFI driver with run-time services",
   "An EFI ROM image",
   "XBOX",
   "unknown",
   "Windows boot application"
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
   printf("created: %s", ctime(&creat));
   printf("symtab offset: %u\n", h->offset_symtab);
   printf("num symbols: %u\n", h->num_symbols);
   printf("exe header size: %u\n", h->size_optional_hdr);
   printf("flags: 0x%X\n", h->flags);
   for (int i=0; i < sizeof(h->flags)*8; i++)
      if (h->flags & 1<<i)
         printf("   - %s\n", flags_lookup[i]);
}

void dump_optional(optional_header* h, unsigned short state)
{
   printf("state: ");
   switch(state)
   {
   case STATE_ID_NORMAL:
      printf("PE32\n");
      break;
   case STATE_ID_ROM:
      printf("PE ROM\n");
      break;
   case STATE_ID_PE32PLUS:
      printf("PE32+\n");   
      break;
   default:
      printf("Unknown\n");
   }
   printf("link ver: %i.%i\n", h->major_linker_ver, h->minor_linker_ver);
   printf("code size: %i\n", h->code_size);
   printf("data size: %i\n", h->data_size);
   printf("uninit data size: %i\n", h->uninit_data_size);
   printf("entry: 0x%x\n", h->entry);
   printf("code base: 0x%x\n", h->code_base);
   if (state == STATE_ID_NORMAL)
      printf("date base: 0x%x\n", h->data_base);
}

void dump_pe32_windows(pe32_windows_header* h)
{
   printf("Base: 0x%x\n", h->base);
   printf("Section alignment: %u\n", h->section_alignment);
   unsigned int file_alignment;
   printf("OS version: %u.%u\n", h->os_major, h->os_minor);
   printf("Image version: %u.%u\n", h->image_major, h->image_minor);
   printf("Subsystem version: %u.%u\n", h->subsys_major, h->subsys_minor);
   //unsigned int image_size;
   //unsigned int header_size;
   //unsigned int checksum;
   if (h->subsystem >= IMAGE_SUBSYSTEM_MAX)
      h->subsystem = 0;
   printf("Subsystem: %s\n", subsystem_lookup[h->subsystem]); // see IMAGE_SUBSYSTEM_
   //unsigned short dll_chars;
   //unsigned int stack_size;
   //unsigned int stack_commit_size;
   //unsigned int heap_size;
   //unsigned int heap_commit_size;
   //unsigned int loader_flags;
   //unsigned int num_rva;
}

void dump_data_dirs(data_dirs* h)
{
   printf("Export: 0x%x (%u)\n", h->export.address, h->export.size);
   printf("Import: 0x%x (%u)\n", h->import.address, h->import.size);
}

static char* coff_symbol_name(symbol* s, char* stringtab)
{
   static char nametmp[10];
   char* name;
   if (s->name.ptr.zeros == 0)
      name = stringtab + s->name.ptr.index;
   else
   {
      memcpy(nametmp, s->name.str, 8);
      nametmp[8] = 0;
      name = nametmp;
   }
   return name;
}

void dump_symtab(symbol* symtab, unsigned int count, char* stringtab)
{
   int aux=0;
   for (unsigned int i=0; i< count; i++)
   {
      symbol* s = &(symtab[i]);
      char* name=coff_symbol_name(s, stringtab);
      aux = s->auxsymbols;
      while (aux)
      {
         // decode as aux
         i++;
         if (s->class == SYM_CLASS_FILE)
         {
            char nametmp[19];
            // COFF symbols of type file should have the name ".file"
            if (strcmp(name, ".file"))
               printf("Got a symbol of type file without name .file! (named %s)\n", name);
            // now get its real name
            memcpy(nametmp, (char*)(&symtab[i]), 18);
            nametmp[18] = 0;
            name = nametmp;
         }
            
         //AUX tagndx 0 ttlsiz 0x0 lnnos 0 next 0
         aux--;
      }
      printf("[%3u](sec %2i)(fl 0x00)(ty %3x)(scl %3i) (nx %i) 0x%08x %s\n", i, s->section, s->type, s->class, s->auxsymbols, s->val, name);
   }
}

static void dump_sections(section_header* secs, unsigned int nsec)
{
   for (unsigned int i=0; i < nsec; i++)
   {
      printf("Section Name: %s\n", secs[i].name);
      printf("Size in mem: %u\n", secs[i].size_in_mem);
      printf("Address: 0x%x\n", secs[i].address);
      printf("Data ptr: %u\n", secs[i].data_offset); 
      printf("Flags: 0x%x\n", secs[i].flags);
   }
}

backend_object* coff_read_file(const char* filename)
{
   char* buff = malloc(sizeof(coff_header));

   FILE* f = fopen(filename, "rb");
   if (!f)
   {
      printf("can't open file\n");
      free(buff);
      return 0;
   }

   // get size of the file
   fseek(f, 0, SEEK_END);
   int fsize = ftell(f);

   if (MAGIC_LOCATOR >= fsize)
   {
      free(buff);
      return 0;
   }

   // read location 0x3C to find the offset of the magic number
   fseek(f, MAGIC_LOCATOR, SEEK_SET);
   fread(buff, MAGIC_SIZE, 1, f);
   if (*(unsigned int*)buff >= fsize)
   {
      free(buff);
      return 0;
   }

   fseek(f, *(unsigned int*)buff, SEEK_SET);
   fread(buff, MAGIC_SIZE, 1, f);
   if (memcmp(buff, PE_MAGIC, 4) != 0)
   {
      free(buff);
      return 0;
   }
   
   printf("found PE magic number\n");
   
   backend_object* obj = backend_create();
   if (!obj)
   {
      free(buff);
      return 0;
   }

   // read the coff header
   coff_header ch;
   fread(&ch, sizeof(coff_header), 1, f);
   dump_coff(&ch);

   unsigned short state; // STATE_ID_
   fread(&state, sizeof(state), 1, f);

   // read the optional header
   free(buff);
   switch(state)
   {
   case STATE_ID_NORMAL:
      backend_set_type(obj, OBJECT_TYPE_PE32);
      // read the optional header
      buff = malloc(sizeof(optional_header));
      fread(buff, sizeof(optional_header), 1, f);
      dump_optional((optional_header*)buff, state);

      // read the windows-specific header
      free(buff);
      buff = malloc(sizeof(pe32_windows_header));
      fread(buff, sizeof(pe32_windows_header), 1, f);
      dump_pe32_windows((pe32_windows_header*)buff);
      break;

   case STATE_ID_ROM:
      backend_set_type(obj, OBJECT_TYPE_PE_ROM);
      break;

   case STATE_ID_PE32PLUS:
      backend_set_type(obj, OBJECT_TYPE_PE32PLUS);
      free(buff);
      //buff = malloc(sizeof(pe32_windows_header));
      //fread(buff, sizeof(pe32_windows_header), 1, f);
      //dump_pe32plus_windows((pe32_windows_header*)buff);
      break;

   default:
      printf("Unknown\n");
   }

   // read the data directories
   free(buff);
   buff = malloc(sizeof(data_dirs));
   fread(buff, sizeof(data_dirs), 1, f);
   //dump_data_dirs((data_dirs*)buff);

   // read the sections - they are immediately after the optional header
   //printf("There are %u sections\n", ch.num_sections);
   int sectabsize = sizeof(section_header) * ch.num_sections;
   section_header* secs = malloc(sectabsize);
   fread(secs, sectabsize, 1 ,f);
   //dump_sections(secs, ch.num_sections);
   for (unsigned int i=0; i < ch.num_sections; i++)
   {
      // load the data
      fseek(f, secs[i].data_offset, SEEK_SET);
      char* data =  malloc(secs[i].size_on_disk);
      fread(data, secs[i].size_on_disk, 1, f);
      backend_add_section(obj, strndup(secs[i].name, 7), secs[i].size_in_mem, secs[i].address, data, 0);
   }

   // read the symbol table
   int symtabsize = ch.num_symbols * sizeof(symbol);
   symbol* symtab = (symbol*)malloc(symtabsize);
   fseek(f, ch.offset_symtab, SEEK_SET);
   fread(symtab, symtabsize, 1, f);
   // can't dump the symbol table until the string table is read

   // read the string table
   int strtabsize=0;
   fread(&strtabsize, 4, 1, f);
   //printf("string table is %i bytes long\n", strtabsize);
   char* strtab = malloc(strtabsize + sizeof(strtabsize));
   fread(strtab+sizeof(strtabsize), strtabsize, 1, f);
   //dump_symtab(symtab, ch.num_symbols, strtab);

   // fill the generic symbol table
   for (unsigned int i=0; i< ch.num_symbols; i++)
   {
      symbol* s = &(symtab[i]);
      char* name = coff_symbol_name(s, strtab);
      switch (s->class)
      {
      case SYM_CLASS_FILE:
         if (strcmp(name, ".file"))
            printf("Warning: 'file' symbol is not named '.file'!\n");
         backend_add_symbol(obj, strndup((char*)&symtab[++i], 18), s->val, SYMBOL_TYPE_FILE, 0, NULL);
         break;

      case SYM_CLASS_SECTION:
      case SYM_CLASS_STATIC:
         // backend_add_symbol(obj, name, s->val, type, flags);
         break;

      case SYM_CLASS_FUNCTION:
         break;

      case SYM_CLASS_EXTERNAL:
         if (s->type != 0x20)
            break;
         if (s->section <= 0)
         {
            printf("Warning: external symbol %s does not have a valid section number\n", name);
            break;
         }
         backend_add_symbol(obj, strndup(name, 8), s->val, SYMBOL_TYPE_FILE, 0, NULL); //TODO look up section
         break;
      }
   }

   // clean up
   free(strtab);
   free(symtab);
   free(buff);

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
