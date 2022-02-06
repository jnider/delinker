/* http://www.delorie.com/djgpp/doc/exe/
MS-DOS EXE format
(The so-called MZ format)
http://files.shikadi.net/malv/files/unlzexe.c - for LZ90 + LZ91 decompression
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "backend.h"
#include "config.h"

#pragma pack(1)

#ifdef DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT //
#endif

#define MZ_MAGIC "\x4d\x5a"
#define MZ_MAGIC_SIZE 2
#define PARAGRAPH_SIZE 16

int unpack (FILE *f, FILE *ofile);
int rdhead (FILE *f ,int *ver);
void wrhead (FILE *ofile);
int mkreltbl (FILE *ifile, FILE *ofile, int ver);

enum compression
{
	MZ_COMPRESSION_NONE,
	MZ_COMPRESSION_LZ90,
	MZ_COMPRESSION_LZ91
};

typedef struct mz_header
{
	unsigned short magic; // see MZ_MAGIC
	unsigned short bytes_in_last_block;
	unsigned short blocks_in_file;
	unsigned short num_relocs;
	unsigned short header_paragraphs;
	unsigned short min_extra_paragraphs;
	unsigned short max_extra_paragraphs;
	unsigned short ss;
	unsigned short sp;
	unsigned short checksum;
	unsigned short ip;
	unsigned short cs;
	unsigned short reloc_table_offset;
	unsigned short overlay_number;
	unsigned char compression[4];
} mz_header;

struct EXE_RELOC {
  unsigned short offset;
  unsigned short segment;
};

void dump_mz_header(const mz_header *h)
{
	fprintf(stderr, "Magic: %X\n", h->magic);
	fprintf(stderr, "Bytes in last block: %i\n", h->bytes_in_last_block);
	fprintf(stderr, "Blocks in file: %i\n", h->blocks_in_file);
	fprintf(stderr, "# relocations: %i\n", h->num_relocs);
	fprintf(stderr, "# paragraphs in header: %i\n", h->header_paragraphs);
	fprintf(stderr, "min extra paragraphs: %i\n", h->min_extra_paragraphs);
	fprintf(stderr, "max extra paragraphs: %i\n", h->max_extra_paragraphs);
	fprintf(stderr, "Stack segment (SS): 0x%04x\n", h->ss);
	fprintf(stderr, "Stack pointer (SP): 0x%04x\n", h->sp);
	fprintf(stderr, "Instruction pointer (IP): 0x%04x\n", h->ip);
	fprintf(stderr, "Code segment (CS): %x\n", h->cs);
	fprintf(stderr, "Relocation table offset: 0x%x\n", h->reloc_table_offset);
	fprintf(stderr, "# overlays: %i\n", h->overlay_number);
	fprintf(stderr, "Checksum: 0x%x\n", h->checksum);
	fprintf(stderr, "Compression: %c%c%c%c\n", h->compression[0], h->compression[1], h->compression[2], h->compression[3]);
}

static backend_object* mz_read_file(const char* filename)
{
   int fsize;
	int exe_size;
	unsigned char *data;
	int sec_size;
   backend_arch be_arch;
	backend_section *s;
   backend_object* obj = NULL;
   char* buff = (char*)malloc(sizeof(mz_header));
	mz_header *h;

   FILE* f = fopen(filename, "rb");
   if (!f)
   {
      printf("can't open file\n");
      goto done;
   }

   // get size of the file
   fseek(f, 0, SEEK_END);
   fsize = ftell(f);
   fseek(f, 0, SEEK_SET);

	// read the file header
	printf("Reading header\n");
	if (fread(buff, 1, sizeof(mz_header), f) != sizeof(mz_header))
	{
		printf("Error reading mz header\n");
      goto done;
	}

	if (memcmp(buff, MZ_MAGIC, MZ_MAGIC_SIZE) != 0)
	{
		printf("Error in MZ magic 0x%x\n", *(unsigned short *)buff);
      goto done;
	}

	h = (mz_header *)buff;

	// validate the file size with the stored EXE size
	exe_size = (h->blocks_in_file - 1) * 512 + h->bytes_in_last_block;
	if (exe_size != fsize)
		printf("Warning: got EXE size %u (expected %u)\n", exe_size, fsize);
	
   obj = backend_create();
   if (!obj)
      goto done;

   backend_set_type(obj, OBJECT_TYPE_MZ);
   be_arch = OBJECT_ARCH_X86;

   if (config.verbose)
		fprintf(stderr, "Arch %i\n", be_arch);
   backend_set_arch(obj, be_arch);

	// decompress if compressed
	int ver;
	if (rdhead(f,&ver)==0)
	{
		FILE *ofile;
		char opath[FILENAME_MAX];

		printf ("compressed by LZEXE v0.%d\n", ver);

		// open output file
		snprintf(opath, FILENAME_MAX, "/tmp/asdf.exe");
		if (!(ofile=fopen(opath,"w+b")))
		{
			printf("can't open output file %s\n", opath);
			goto done;
		}

		if (mkreltbl (f,ofile,ver)!=0)
		{
			printf("Can't make rel table\n");
			fclose (ofile);
			remove (opath);
			goto done;
      }

		if(unpack (f,ofile)!=0)
		{
			printf("Can't unpack\n");
			fclose (ofile);
			remove (opath);
			goto done;
      }
    	wrhead (ofile);
    	fclose (ofile);
    	fclose (f);
		f = fopen(opath, "rb");
   	fseek(f, 0, SEEK_SET);

		// read the file header
		printf("Reading header\n");
		if (fread(buff, 1, sizeof(mz_header), f) != sizeof(mz_header))
		{
			if (config.verbose)
				printf("Error reading mz header\n");
	      goto done;
		}
	}
	dump_mz_header(h);

	sec_size =  fsize - PARAGRAPH_SIZE * h->header_paragraphs;
	data = (unsigned char*)malloc(sec_size);
	fseek(f, PARAGRAPH_SIZE * h->header_paragraphs, SEEK_SET);
	if (fread(data, 1, sec_size, f) != sec_size)
	{
		fprintf(stderr, "Error loading exe section\n");
		free(data);
		goto done;
	}

	backend_set_entry_point(obj, (h->cs * PARAGRAPH_SIZE) + h->ip);

	// we only have one input 'section' - mixed code & data, but we want to separate them
	// start with a duplicate, and cut the unnecessary pieces later
	s = backend_add_section(obj, ".data", sec_size, 0, data, 0, 1, SECTION_FLAG_INIT_DATA);
	backend_section_set_type(s, SECTION_TYPE_PROG);
	s = backend_add_section(obj, ".text", sec_size, 0, data, 0, 1, SECTION_FLAG_EXECUTE);
	backend_section_set_type(s, SECTION_TYPE_PROG);

done:
	free(buff);
	return obj;
}

const char* mz_name(void)
{
	return "MSDOS";
}

/* identifies the file format we can write */
backend_type mz_format(void)
{
   return OBJECT_TYPE_MZ;
}

backend_ops mz_backend =
{
	.name = mz_name,
   .format = mz_format,
   .read = mz_read_file,
   //.write = mz_write_file
};

void mz_init(void)
{
   backend_register(&mz_backend);
}

