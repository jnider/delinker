/* Old-style EXE aka DOS MZ executable format */
/* http://www.delorie.com/djgpp/doc/exe/ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "backend.h"

#pragma pack(1)

#define MZ_MAGIC "MZ"
#define MAGIC_SIZE 2

#define PARAGRAPH_SIZE 16  // a 'paragraph' is 16 bytes
#define BLOCK_SIZE 512     // a 'block' is 512 bytes

struct mz_header
{
   char magic[2];
   unsigned short last_block_used; // The number of bytes in the last block of the program that are actually used (0 means all).
   unsigned short num_blocks;   // how many blocks in the file are used
   unsigned short num_relocs;   // number of reloc entries following the header
   unsigned short size;         // size of header in paragraphs
   unsigned short memory;       // free memory required by the program (in paragraphs)
   unsigned short max_memory;   // maximum additional memory (in paragraphs)
   unsigned short stack;        // stack offset from program load segment base
   unsigned short sp;           // initial value of the sp register
   unsigned short checksum;     // 16-bit checksum (should be 0)
   unsigned short ip;           // initial value of the ip register (entry point)
   unsigned short cs;           // segment program was loaded at
   unsigned short reloc;        // offset of first relocation in the file
   unsigned short overlay;      // overlay index
};

struct relocation
{
   unsigned short offset;
   unsigned short segment;
};

static void dump_header(struct mz_header *h)
{
   printf("Magic: %c%c\n", h->magic[0], h->magic[1]);
   printf("num bytes in last block: %i\n", h->last_block_used);
   printf("Num blocks: %i\n", h->num_blocks);
   printf("Num relocs: %i\n", h->num_relocs);
   printf("header size: %i\n", h->size * PARAGRAPH_SIZE);
   printf("memory: %i\n", h->memory);
   printf("max_memory: %i\n", h->max_memory);
   printf("ss: 0x%x\n", h->stack);
   printf("sp: 0x%x\n", h->sp);
   printf("ip: 0x%x\n", h->ip);
   printf("cs: 0x%x\n", h->cs);
   printf("reloc offset: %i\n", h->reloc);
}

const char* mz_name(void)
{
	return "mz";
}

/* identifies the file format we can write */
backend_type mz_format(void)
{
   return OBJECT_TYPE_MZ;
}

static backend_object* mz_read_file(const char* filename)
{
   struct mz_header header;
   printf("MZ reading %s\n", filename);

   FILE* f = fopen(filename, "rb");
   if (!f)
   {
      printf("can't open file\n");
      return 0;
   }

   // get size of the file
   fseek(f, 0, SEEK_END);
   int fsize = ftell(f);
   fseek(f, 0, SEEK_SET);

   // read in the whole header
   fread(&header, sizeof(header), 1, f);
   dump_header(&header);

   // check the magic number
   if (memcmp(header.magic, MZ_MAGIC, MAGIC_SIZE) != 0)
      return 0;
   
   printf("found MZ magic number\n");
   backend_object* obj = backend_create();
   if (!obj)
      return 0;

   backend_set_type(obj, OBJECT_TYPE_MZ);

   // Thanks to 8088 segmentation, here's how to get the entry point in linear space
   unsigned int entry = (header.cs << 4) + header.ip;
   backend_set_entry_point(obj, entry);

   // all the rest is a mixture of code & data
   int data_offset = header.size * PARAGRAPH_SIZE;
   int data_size = ((header.num_blocks-1) * BLOCK_SIZE) - data_offset;
   data_size += header.last_block_used ? header.last_block_used : BLOCK_SIZE;
   printf("Reading %i bytes of code/data\n", data_size);

   fseek(f, data_offset, SEEK_SET);
   char* data = malloc(data_size);
   fread(data, data_size, 1, f);

   // we mark the whole thing as code (.text) and figure out the rest later
   backend_add_section(obj, ".text", data_size, 0, data, 0, 2,
      SECTION_FLAG_READ | SECTION_FLAG_CODE | SECTION_FLAG_EXECUTE);
   return obj;
}

backend_ops mz_backend =
{
	.name = mz_name,
   .format = mz_format,
   .read = mz_read_file,
   .write = 0
};

void mz_init(void)
{
   backend_register(&mz_backend);
}
