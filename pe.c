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
#define COFF_FLAG_RELOCS_STRIPPED         0  //Does not contain base relocations and must therefore be loaded at its preferred base address
#define COFF_FLAG_EXECUTABLE_IMAGE        1  //The image file is valid and can be run
#define COFF_FLAG_LINE_NUMS_STRIPPED      2  //COFF line numbers have been removed
#define COFF_FLAG_LOCAL_SYMS_STRIPPED     3  //COFF symbol table entries for local symbols have been removed
#define COFF_FLAG_AGGRESSIVE_WS_TRIM      4  //Obsolete. Aggressively trim working set
#define COFF_FLAG_LARGE_ADDRESS           5  //Application can handle > 2-GB addresses.
#define COFF_FLAG_BYTES_REVERSED_LO       7  //Little endian
#define COFF_FLAG_32BIT_MACHINE           8  //Machine is based on a 32-bit-word architecture.
#define COFF_FLAG_DEBUG_STRIPPED          9  //Debugging information is removed from the image file.
#define COFF_FLAG_REMOVABLE_RUN_FROM_SWAP 10 //If the image is on removable media, fully load it and copy it to the swap file.
#define COFF_FLAG_NET_RUN_FROM_SWAP       11 //If the image is on network media, fully load it and copy it to the swap file.
#define COFF_FLAG_SYSTEM                  12 //The image file is a system file, not a user program.
#define COFF_FLAG_DLL                     13 //The image file is a dynamic-link library (DLL)
#define COFF_FLAG_UP_SYSTEM_ONLY          14 //The file should be run only on a uniprocessor machine.
#define COFF_FLAG_BYTES_REVERSED_HI       15 //Big endian

// the symbol classes
#define SYM_CLASS_EXTERNAL 2
#define SYM_CLASS_STATIC 3 // The offset of the symbol within the section. If the Value field is zero, then the symbol represents a section name.
#define SYM_CLASS_FUNCTION 101
#define SYM_CLASS_FILE 103
#define SYM_CLASS_SECTION 104

// section flags
#define SCN_CNT_CODE                      (1<<SCN_SHIFT_CNT_CODE) // The section contains executable code
#define SCN_CNT_INIT_DATA                 (1<<SCN_SHIFT_CNT_INIT_DATA) // The section contains initialized data
#define SCN_CNT_UNINIT_DATA               (1<<SCN_SHIFT_CNT_UNINIT_DATA) // The section contains uninitialized data
#define SCN_LNK_INFO                      (1<<SCN_SHIFT_LNK_INFO) // The section contains comments or other information.
#define SCN_LNK_REMOVE                    (1<<SCN_SHIFT_LNK_REMOVE) // The section will not become part of the image. This is valid only for object files.
#define SCN_LNK_COMDAT                    (1<<SCN_SHIFT_LNK_COMDAT) // The section contains COMDAT data. This is valid only for object files.
#define SCN_ALIGN                         (0xF<<SCN_SHIFT_ALIGN) 
#define SCN_LNK_NRELOC_OVFL               (1<<SCN_SHIFT_LNK_NRELOC_OVFL) // The section contains extended relocations
#define SCN_MEM_DISCARDABLE               (1<<SCN_SHIFT_MEM_DISCARDABLE) // The section can be discarded as needed
#define SCN_MEM_NOT_CACHED                (1<<SCN_SHIFT_MEM_NOT_CACHED) // The section cannot be cached
#define SCN_MEM_NOT_PAGED                 (1<<SCN_SHIFT_MEM_NOT_PAGED) // The section is not pageable
#define SCN_MEM_SHARED                    (1<<SCN_SHIFT_MEM_SHARED) // The section can be shared in memory
#define SCN_MEM_EXECUTE                   (1<<SCN_SHIFT_MEM_EXECUTE) // The section can be executed as code
#define SCN_MEM_READ                      (1<<SCN_SHIFT_MEM_READ) // The section can be read
#define SCN_MEM_WRITE                     (1<<SCN_SHIFT_MEM_WRITE) // The section can be written to

enum section_flags
{
	SCN_SHIFT_CNT_CODE = 5,
	SCN_SHIFT_CNT_INIT_DATA,
	SCN_SHIFT_CNT_UNINIT_DATA,
	SCN_SHIFT_FLAG_8,
	SCN_SHIFT_LNK_INFO,
	SCN_SHIFT_FLAG_10,
	SCN_SHIFT_LNK_REMOVE,
	SCN_SHIFT_LNK_COMDAT,
	SCN_SHIFT_ALIGN = 20,
	SCN_SHIFT_LNK_NRELOC_OVFL = 24,
	SCN_SHIFT_MEM_DISCARDABLE,
	SCN_SHIFT_MEM_NOT_CACHED,
	SCN_SHIFT_MEM_NOT_PAGED,
	SCN_SHIFT_MEM_SHARED,
	SCN_SHIFT_MEM_EXECUTE,
	SCN_SHIFT_MEM_READ,
	SCN_SHIFT_MEM_WRITE
};

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
   unsigned short flags;         // see COFF_FLAG_
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
   unsigned int flags; // see SCN_
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

typedef struct import_dir
{
	unsigned int lu_table;
	unsigned int timestamp;
	unsigned int forwarder;
	unsigned int name;
	unsigned int addr_table;
} import_dir;

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

static const char* section_flags_lookup[] = 
{
   "",
   "",
   "",
   "",
   "",
   "executable code",
   "initialized data",
   "uninitialized data",
   "comments or other information",
   "will not become part of the image",
   "COMDAT data",
   0,0,0,0,0,0,0,0,0,0,0,0,0,
   "extended relocations",
   "can be discarded as needed",
   "cannot be cached",
   "is not pageable",
   "can be shared in memory",
   "can be executed as code",
   "can be read",
   "can be written to"
};

const char* pe32_name(void)
{
	return "pe32";
}


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
      printf("Alignment: %i\n", (secs[i].flags >> SCN_SHIFT_ALIGN) & SCN_ALIGN);
   }
}

/* identifies the file format we can write */
backend_type pe32_format(void)
{
   return OBJECT_TYPE_PE32;
}

backend_type pe32plus_format(void)
{
   return OBJECT_TYPE_PE32PLUS;
}

static backend_object* pe_read_file(const char* filename)
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
   //dump_coff(&ch);

   unsigned short state; // STATE_ID_
   fread(&state, sizeof(state), 1, f);

	unsigned int entry_offset;
	unsigned int base_address;

   // read the optional header
   free(buff);
   switch(state)
   {
   case STATE_ID_NORMAL:
      backend_set_type(obj, OBJECT_TYPE_PE32);
      // read the optional header
      buff = malloc(sizeof(optional_header));
      fread(buff, sizeof(optional_header), 1, f);
      //dump_optional((optional_header*)buff, state);
		entry_offset = ((optional_header*)buff)->entry;

      // read the windows-specific header
      free(buff);
      buff = malloc(sizeof(pe32_windows_header));
      fread(buff, sizeof(pe32_windows_header), 1, f);
      //dump_pe32_windows((pe32_windows_header*)buff);

		// add generic object information
		base_address = ((pe32_windows_header*)buff)->base;
		backend_set_entry_point(obj, base_address + entry_offset);
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
   data_dirs* dd = malloc(sizeof(data_dirs));
   fread(dd, sizeof(data_dirs), 1, f);
   dump_data_dirs(dd);

   // read the sections - they are immediately after the optional header
	char tmp_name[32];
	unsigned int import_file_base; // file offset of section containing the import info
	backend_section* import_sec; // pointer to the section containing the import info
   printf("There are %u sections\n", ch.num_sections);
   int sectabsize = sizeof(section_header) * ch.num_sections;
   section_header* secs = malloc(sectabsize);
   fread(secs, sectabsize, 1 ,f);
   //dump_sections(secs, ch.num_sections);
   for (unsigned int i=0; i < ch.num_sections; i++)
   {
      // load the data
      fseek(f, secs[i].data_offset, SEEK_SET);
      char* data = malloc(secs[i].size_on_disk);
      fread(data, secs[i].size_on_disk, 1, f);

      // convert the flags
      unsigned int flags=0;
      if (secs[i].flags & SCN_CNT_CODE)
         flags |= SECTION_FLAG_CODE;
      if (secs[i].flags & SCN_CNT_INIT_DATA)
         flags |= SECTION_FLAG_INIT_DATA;
      if (secs[i].flags & SCN_CNT_UNINIT_DATA)
         flags |= SECTION_FLAG_UNINIT_DATA;
      if (secs[i].flags & SCN_LNK_INFO)
         flags |= SECTION_FLAG_COMMENTS;
      if (secs[i].flags & SCN_LNK_REMOVE)
         flags |= SECTION_FLAG_DISCARDABLE;
      if (secs[i].flags & SCN_MEM_EXECUTE)
         flags |= SECTION_FLAG_EXECUTE;
      if (secs[i].flags & SCN_MEM_READ)
         flags |= SECTION_FLAG_READ;
      if (secs[i].flags & SCN_MEM_WRITE)
         flags |= SECTION_FLAG_WRITE;

		strncpy(tmp_name, secs[i].name, 8);
		printf("Section %s has flags: 0x%x\n", tmp_name, secs[i].flags);

		// update the known names to have a consistent naming in the backend
		if (strcmp(tmp_name, ".rdata") == 0)
		{
			printf("PE: replacing .rdata with .rodata\n");
			strcpy(tmp_name, ".rodata");
		}

		// add the backend section
      backend_section* sec = backend_add_section(obj, tmp_name, secs[i].size_in_mem, base_address + secs[i].address, data, 0, (secs[i].flags >> SCN_SHIFT_ALIGN) & SCN_ALIGN, flags);

		// find out which section contains the import names (if we have imports)
		if (dd->import.address && secs[i].data_offset <= dd->import.address && secs[i].data_offset + secs[i].size_in_mem > dd->import.address)
		{
			printf("Section %s (base=0x%x) has imports\n", secs[i].name, secs[i].data_offset);
			import_file_base = secs[i].data_offset;
			import_sec = sec;
		}
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

      // is this a function?
      if (s->type == 0x20)
      {
         if (s->class == SYM_CLASS_EXTERNAL && s->section <= 0)
         {
            printf("Warning: external symbol %s does not have a valid section number\n", name);
            break;
         }
         if (s->auxsymbols == 1)
            i++; // the aux doesn't seem to be in use by MSFT, so I'm not going to bother reading it now
			// this strndup is leaking memory - fix it. It is duplicated again inside the call. also a few more down below in calls to add_symbol.
         backend_add_symbol(obj, strndup(name, 8), s->val, SYMBOL_TYPE_FUNCTION, 0, 0, backend_get_section_by_index(obj, s->section));
      }
      else
      {
         switch (s->class)
         {
         case SYM_CLASS_FILE:
            if (strcmp(name, ".file"))
               printf("Warning: 'file' symbol is not named '.file'!\n");
            backend_add_symbol(obj, strndup((char*)&symtab[++i], 18), s->val, SYMBOL_TYPE_FILE, 0, 0, NULL);
            break;

         case SYM_CLASS_SECTION:
            break;

         case SYM_CLASS_STATIC:
            if (s->auxsymbols == 1)
            {
               // read the number of relocations
               //symbol_aux_sec* a = &(symtab[++i]);
               i++; // remove this when uncommenting previous line
            }
            backend_add_symbol(obj, strndup(name, 8), s->val, SYMBOL_TYPE_SECTION, 0, 0, NULL);
            // here we probably need to update the section object as well
            break;

         case SYM_CLASS_FUNCTION:
            // these are the .bf (begin function) and .ef (end function) symbols - ignore them for now
            break;

         case SYM_CLASS_EXTERNAL:
            break;
         }
      }
   }

	backend_section* sec_text = backend_get_section_by_name(obj, ".text");
	if (!sec_text)
	{
		printf("Can't find code section!\n");
		goto done;
	}

	// read the import directory table
	unsigned long next;
	import_dir dir;
	unsigned int lu;
	backend_import* mod;
	fseek(f, dd->import.address, SEEK_SET);
	fread(&dir, sizeof(import_dir), 1, f);
	while (dir.lu_table && dir.addr_table)
	{
		char* name = import_sec->data + (dir.name - import_file_base);
		//printf("Module: %s Table @ 0x%x\n", name, dir.addr_table);
		mod = backend_add_import_module(obj, name);
		next = ftell(f);

		// read the import address table
		fseek(f, dir.addr_table, SEEK_SET);
		fread(&lu, sizeof(unsigned int), 1, f);
		unsigned long val = (unsigned long)import_sec->address + (dir.addr_table - import_file_base);
		while (lu)
		{
			if (lu & 0x80000000)
			{
				char tmp_name[10];

				sprintf(tmp_name, "0x%x", lu & 0xFFFF);
				backend_add_import_function(mod, name, val);
			}
			else
			{
				name = import_sec->data + ((lu & 0x7FFFFFFF) - import_file_base) + 2;

				printf("Adding import function: %s @ 0x%lx\n", name, val);
				backend_add_import_function(mod, name, val);
				backend_add_symbol(obj, name, 0, SYMBOL_TYPE_NONE, 0, SYMBOL_FLAG_GLOBAL | SYMBOL_FLAG_EXTERNAL, sec_text);
			}
			fread(&lu, sizeof(unsigned int), 1, f);
			val += sizeof(unsigned int);
		}

		// get the next one
		fseek(f, next, SEEK_SET);
		fread(&dir, sizeof(import_dir), 1, f);
	}

done:
   // clean up
   free(strtab);
   free(symtab);
   free(buff);

	printf("PE32 loading done (%i symbols, %i relocs)\n", backend_symbol_count(obj), backend_relocation_count(obj));
	printf("-----------------------------------------\n");
   return obj;
}

/* We must calculate the symbol count differently in COFF in order to take AUX
symbols into account. Some symbols are written using multiple entries, so there
can be a primary entry and 0 or more aux entries for each symbol */
static unsigned int coff_symbol_count(backend_object* obj)
{
   unsigned int count=0;
   backend_symbol* sym = backend_get_first_symbol(obj);
   while (sym)
   {
      count++; // for the primary symbol
      switch (sym->type)
      {
      case SYMBOL_TYPE_FILE:
         if (sym->section == 0)
            count++; // aux type 4
         break;
      case SYMBOL_TYPE_SECTION:
         count++; // aux type 5
         break;
      case SYMBOL_TYPE_FUNCTION:
         count++; // aux format 1
         break;
      }
      //printf("counting symbol %s (%u)\n", sym->name, count);
      sym = backend_get_next_symbol(obj);
   }
   return count;
}

static int coff_write_file(backend_object* obj, const char* filename)
{
   FILE* f = fopen(filename, "wb");
   if (!f)
   {
      printf("can't open file\n");
      return -1;
   }

   // fill and write the coff header
   printf("writing COFF header\n");
   coff_header ch;
   ch.machine = IMAGE_FILE_MACHINE_I386;
   ch.num_sections = backend_section_count(obj);
   ch.time_created = time(NULL);
   ch.offset_symtab = sizeof(coff_header) + sizeof(section_header)*backend_section_count(obj);
   printf("counting symbols\n");
   ch.num_symbols = coff_symbol_count(obj);
	printf("setting count to %i symbols\n", ch.num_symbols);
   ch.size_optional_hdr = 0;
   ch.flags = (1<<COFF_FLAG_32BIT_MACHINE) | (1<<COFF_FLAG_DEBUG_STRIPPED);
   fwrite(&ch, sizeof(coff_header), 1, f);

   // section table immediately follows the COFF header
   printf("writing %u sections\n", backend_section_count(obj));
   backend_section* sec = backend_get_first_section(obj);
   while (sec)
   {
      section_header sh;
      printf("Writing section %s\n", sec->name);
      strncpy(sh.name, sec->name, 9); // yes, we want the null to go one past the end of buffer
      sh.size_in_mem = sec->size;
      sh.address = sec->address;
      sh.data_offset = ch.offset_symtab + ch.num_symbols*sizeof(symbol) + 0; // after the string table
      sh.reloc = 0;
      sh.linenums = 0;
      sh.num_reloc = 0;
      sh.num_lines = 0;
      
      // section alignment
      sh.flags = (sec->alignment & SCN_ALIGN) << SCN_SHIFT_ALIGN;

      // convert the flags
      if (sec->flags & SECTION_FLAG_CODE)
         sh.flags |= SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ;
      if (sec->flags & SECTION_FLAG_INIT_DATA)
         sh.flags |= SCN_CNT_INIT_DATA |SCN_MEM_READ | SCN_MEM_WRITE;
      if (sec->flags & SECTION_FLAG_UNINIT_DATA)
         sh.flags |= SCN_CNT_UNINIT_DATA |SCN_MEM_READ | SCN_MEM_WRITE;
      if (sec->flags & SECTION_FLAG_COMMENTS)
         sh.flags |= SCN_LNK_INFO |SCN_LNK_REMOVE;
      if (sec->flags & SECTION_FLAG_DISCARDABLE)
         sh.flags |= SCN_LNK_REMOVE;

      printf("writing section header\n");
      fwrite(&sh, sizeof(section_header), 1, f);
      sec = backend_get_next_section(obj);
   }

   // symbol table
   backend_symbol* sym = backend_get_first_symbol(obj);
   while (sym)
   {
      symbol s;
      memcpy(s.name.str, sym->name, 8);
      s.val = sym->val;
      //JKN - fix this. it should call backend_get_section_index() s.section = sym->section->index;
      s.auxsymbols = 0;
      switch (sym->type)
      {
      case SYMBOL_TYPE_FILE:
         s.type = 0x20;
         s.class = SYM_CLASS_FILE;
         s.section = -2;
         break;
      case SYMBOL_TYPE_SECTION:
         s.type = 0;
         s.class = SYM_CLASS_STATIC;
         break;
      case SYMBOL_TYPE_FUNCTION:
         s.type = 0;
         s.class = SYM_CLASS_EXTERNAL;
         break;
      }
      fwrite(&s, sizeof(symbol), 1, f);
      sym = backend_get_next_symbol(obj);
   }

   // string table immediately follows the symbol table

   fclose(f);
   return 0;
}

static const char pe_header[] =
{
 0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
 0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
 0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
 0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static int pe32_write_file(backend_object* obj, const char* filename)
{
   FILE* f = fopen(filename, "wb");
   if (!f)
   {
      printf("can't open file\n");
      return -1;
   }

   // write file header
   char buff[4];
   fwrite(&pe_header, sizeof(pe_header), 1, f);
   memcpy(buff, PE_MAGIC, MAGIC_SIZE);
   fwrite(buff, MAGIC_SIZE, 1, f);

   // fill and write the coff header
   printf("writing PE file\n");
   coff_header ch;
   ch.machine = IMAGE_FILE_MACHINE_I386;
   ch.num_sections = backend_section_count(obj);
   ch.time_created = time(NULL);
   ch.offset_symtab = sizeof(coff_header) + sizeof(optional_header) + +sizeof(pe32_windows_header) + sizeof(data_dirs) + sizeof(section_header)*backend_section_count(obj);
   printf("counting symbols\n");
   ch.num_symbols = coff_symbol_count(obj);
	printf("setting count to %i symbols\n", ch.num_symbols);
   ch.size_optional_hdr = sizeof(optional_header);
   ch.flags = (1<<COFF_FLAG_32BIT_MACHINE) | (1<<COFF_FLAG_DEBUG_STRIPPED) | (1<<COFF_FLAG_EXECUTABLE_IMAGE);
   fwrite(&ch, sizeof(coff_header), 1, f);

   unsigned short state = STATE_ID_NORMAL; // STATE_ID_
   fwrite(&state, sizeof(state), 1, f);

   // standard optional header
   optional_header oh;
   oh.major_linker_ver=9;
   oh.minor_linker_ver=87;
   oh.code_size=6666;
   oh.data_size=7777;
   oh.uninit_data_size=1111;
   oh.entry=2222;
   oh.code_base=1234;
   oh.data_base=4567;
   fwrite(&oh, sizeof(optional_header), 1, f);

   // windows optional header
   pe32_windows_header wh;
   wh.base = 0;
   wh.section_alignment = 1;
   wh.file_alignment = 1;
   wh.os_major=8;
   wh.os_minor=1;
   wh.subsystem = IMAGE_SUBSYSTEM_POSIX_CUI;
   fwrite(&wh, sizeof(pe32_windows_header), 1, f);

   // data dirs
   data_dirs dd;
   fwrite(&dd, sizeof(data_dirs), 1, f);

   // section table immediately follows the COFF header
   printf("writing %u sections\n", backend_section_count(obj));
   backend_section* sec = backend_get_first_section(obj);
   while (sec)
   {
      section_header sh;
      printf("Writing section %s\n", sec->name);
      strncpy(sh.name, sec->name, 9); // yes, we want the null to go one past the end of buffer
      sh.size_in_mem = sec->size;
      sh.address = sec->address;
      sh.data_offset = ch.offset_symtab + ch.num_symbols*sizeof(symbol) + 0; // after the string table
      sh.reloc = 0;
      sh.linenums = 0;
      sh.num_reloc = 0;
      sh.num_lines = 0;
      
      // section alignment
      sh.flags = (sec->alignment & SCN_ALIGN) << SCN_SHIFT_ALIGN;

      // convert the flags
      if (sec->flags & SECTION_FLAG_CODE)
         sh.flags |= SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ;
      if (sec->flags & SECTION_FLAG_INIT_DATA)
         sh.flags |= SCN_CNT_INIT_DATA |SCN_MEM_READ | SCN_MEM_WRITE;
      if (sec->flags & SECTION_FLAG_UNINIT_DATA)
         sh.flags |= SCN_CNT_UNINIT_DATA |SCN_MEM_READ | SCN_MEM_WRITE;
      if (sec->flags & SECTION_FLAG_COMMENTS)
         sh.flags |= SCN_LNK_INFO |SCN_LNK_REMOVE;
      if (sec->flags & SECTION_FLAG_DISCARDABLE)
         sh.flags |= SCN_LNK_REMOVE;

      printf("writing section header\n");
      fwrite(&sh, sizeof(section_header), 1, f);
      sec = backend_get_next_section(obj);
   }

   // symbol table
	printf("writing symbol table\n");
   backend_symbol* sym = backend_get_first_symbol(obj);
   while (sym)
   {
		char tmp[19];
      symbol s;
      s.val = sym->val;
      //JKN - fix this. it should call backend_get_section_index() s.section = sym->section->index;
      s.auxsymbols = 0;
      switch (sym->type)
      {
      case SYMBOL_TYPE_FILE:
			printf("writing file symbol %s\n", sym->name);
         s.type = 0x20;
         s.class = SYM_CLASS_FILE;
         s.section = -2;
			s.auxsymbols = 1;
			memcpy(s.name.str, ".file", 6);
			fwrite(&s, sizeof(symbol), 1, f);
			memcpy(tmp, sym->name, 19);
			fwrite(tmp, 18, 1, f);
         break;

      case SYMBOL_TYPE_SECTION:
			memcpy(s.name.str, sym->name, 8);
         s.type = 0;
         s.class = SYM_CLASS_STATIC;
			s.auxsymbols = 1;
         break;

      case SYMBOL_TYPE_FUNCTION:
      	memcpy(s.name.str, sym->name, 8);
         s.type = 0;
         s.class = SYM_CLASS_EXTERNAL;
			s.auxsymbols = 1;
         break;
      }
      sym = backend_get_next_symbol(obj);
   }

   // string table immediately follows the symbol table

   fclose(f);
   return 0;
}
backend_ops pe32_backend =
{
	.name = pe32_name,
   .format = pe32_format,
   .read = pe_read_file,
   //.write = coff_write_file
   .write = pe32_write_file
};

backend_ops pe32plus_backend =
{
   .format = pe32plus_format,
   .read = pe_read_file
};

void pe_init(void)
{
   backend_register(&pe32_backend);
   //backend_register(&pe32plus_backend);
}
