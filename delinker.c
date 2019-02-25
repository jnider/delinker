/* J.Nider 27/07/2017
I tried for so long to get BFD to work, but it is just not built well enough
to be used for other tasks. There are too many format-specific flags and
behaviours that just make life difficult, which is why I am writing my own
backend from scratch. */

/* The idea of the program is simple - read in a fully linked executable,
and write out a set of unlinked .o files that can be relinked later.*/

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "capstone/capstone.h"
#include "backend.h"

#define DEFAULT_OUTPUT_FILENAME "default.o"
#define SYMBOL_NAME_MAIN "main"

enum error_codes
{
   ERR_NONE,
   ERR_BAD_FILE,
   ERR_BAD_FORMAT,
   ERR_NO_SYMS,
   ERR_NO_SYMS_AFTER_RECONSTRUCT,
   ERR_NO_TEXT_SECTION,
   ERR_NO_PLT_SECTION,
	ERR_CANT_CREATE_OO,
};

static struct option options[] =
{
  {"output-target", required_argument, 0, 'O'},
  {"reconstruct-symbols", no_argument, 0, 'R'},
  {0, no_argument, 0, 0}
};

struct config
{
   int reconstruct_symbols;
} config;

static void
usage(void)
{
   fprintf(stderr, "Unlinker performs the opposite action to 'ld'. It accepts a binary executable as input, and\n");
   fprintf(stderr, "creates a set of .o files that can be relinked.\n");
   fprintf(stderr, "unlinker <input file>\n\n\n");
   fprintf(stderr, "Supported backend targets:\n");
	const char* t = backend_get_first_target();
	while (t)
	{
		fprintf(stderr, "%s\n", t);
		t = backend_get_next_target();
	}
}

// make sure all function symbols are in increasing order, without any overlaps
static int check_function_sequence(backend_object* obj)
{
	unsigned long curr = 0;
   backend_symbol* sym = backend_get_first_symbol(obj);
	while (sym)
	{
		if (sym->type == SYMBOL_TYPE_FUNCTION)
		{
			//printf("sym: %s\t\t0x%lx -> 0x%lx\n", sym->name, sym->val, sym->val+sym->size);
			if (sym->val < curr)
			{
				printf("Overlap detected @ 0x%lx!\n", sym->val);
				return -1;
			}
			curr = sym->val + sym->size;
		}
      sym = backend_get_next_symbol(obj);
	}

	return 0;
}

static int reconstruct_symbols(backend_object* obj, int padding)
{
	csh handle;
	cs_insn *cs_obj;

	printf("reconstructing symbols from text section\n");
   /* find the text section */
   backend_section* sec_text = backend_get_section_by_name(obj, ".text");
   if (!sec_text)
      return -ERR_NO_TEXT_SECTION;

	// add a fake symbol for the filename
	backend_add_symbol(obj, "source.c", 0, SYMBOL_TYPE_FILE, 0, 0, sec_text);

	unsigned int start_count = backend_symbol_count(obj);

	// decode (disassemble) the executable section, and assume that any instruction following a 'ret'
   // is the beginning of a new function. Create a symbol entry at that address, and add it to the list.
	// We must also handle 'jmp' instructions in the middle of nowhere (jump tables?) in the same way.
	char name[16];
	unsigned int sym_addr = 0;
	unsigned int length;
	int eof = 0;
	size_t ins_count, j;

	sprintf(name, "fn%06X", 0);

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return -1;

	ins_count = cs_disasm(handle, sec_text->data, sec_text->size, 0, 0, &cs_obj);

	//while (length = ud_disassemble(&ud_obj))
	for (j=0; j < ins_count; j++)
	{
		enum ud_mnemonic_code mnem;
		mnem = ud_insn_mnemonic(&ud_obj);
		unsigned int addr = ud_insn_off(&ud_obj);

		// did we hit the official end of the function?
		//if (mnem == UD_Iret || mnem == UD_Ijmp)
		if (mnem == UD_Iret)
		{
			eof = 1;

			// ignore any extraneous bytes after the 'ret' instruction
			if (!padding)
				backend_add_symbol(obj, name, sec_text->address + sym_addr, SYMBOL_TYPE_FUNCTION, addr - sym_addr, SYMBOL_FLAG_GLOBAL, sec_text);
			continue;
		}

		// the next 'valid' instruction starts the next function
		if (eof)
		{
			if (mnem == UD_Iint3 || mnem == UD_Inop)
				continue;
			else
			{
				// the first instruction after the end of a function - start a new function, and add
				// the previous one to the list
				eof = 0;

				if (padding)
					backend_add_symbol(obj, name, sec_text->address + sym_addr, SYMBOL_TYPE_FUNCTION, addr - sym_addr, SYMBOL_FLAG_GLOBAL, sec_text);
				//printf("Adding function length=0x%x\n", addr - sym_addr);

				sprintf(name, "fn%06X", addr);
				sym_addr = addr;
				//printf("Starting new function at 0x%x\n", addr);
			}
		}
	}

	// If we have reconstructed symbols and we want to be able to link again later, the linker is going to
	// look for a symbol called 'main'. We must rename the symbol at the original entry point to be called main.
	// This is practically the only symbol that we can recover the name for without major decompiling efforts.
	backend_symbol *bs = backend_find_symbol_by_val_type(obj, backend_get_entry_point(obj), SYMBOL_TYPE_FUNCTION);
	if (bs)
	{
		printf("found entry point %s @ 0x%lx - renaming to 'main'\n", bs->name, bs->val);
		free(bs->name);
		bs->name = strdup(SYMBOL_NAME_MAIN);
	}
	else
	{
		printf("No symbol for entry point @ 0x%lx - the recovery is not very accurate\n", backend_get_entry_point(obj));
		bs = backend_find_nearest_symbol(obj, backend_get_entry_point(obj));
		printf("%s @ 0x%lx is the closest - splitting\n", bs->name, bs->val);
      backend_split_symbol(obj, bs, SYMBOL_NAME_MAIN, backend_get_entry_point(obj), SYMBOL_TYPE_FUNCTION, 0);
	}

	printf("%u symbols recovered\n", backend_symbol_count(obj) - start_count);

   return 0;
}

/* the data buffer likely includes code that we don't need */
static int fixup_function_data(backend_object* obj)
{
	backend_symbol* sym;
	unsigned long curr = 0;
	int offset = -1;

	//printf("fixup_function_data %i\n", backend_symbol_count(obj));

	if (check_function_sequence(obj) != 0)
		return -1;

	// find the the .text section (containing code)
	backend_section* code = backend_get_section_by_name(obj, ".text");
	if (!code)
	{
		printf("Can't find .text section\n");
		return -2;
	}

	//printf(".text section base = 0x%lx\n", code->address);
	// now compact the code (curr is the offset)
	sym = backend_get_first_symbol(obj);
	while (sym)
	{
		if (sym->type == SYMBOL_TYPE_FUNCTION)
		{
			// if a symbol has 0 length, skip it
			if (sym->size && sym->val != curr)
			{
				if (offset == -1)
					offset = sym->val;

				//printf("Moving function @ 0x%lx to 0x%lx (size %lu)\n", sym->val, sym->val - offset, sym->size);
				//printf("memmove %p, %p (size %lu)\n", code->data + sym->val - offset, code->data + sym->val, sym->size);
				memmove(code->data + sym->val - offset, code->data + sym->val, sym->size);
				sym->val -= offset; // update the symbol address
			}
			curr = sym->val + sym->size;
		}
		sym = backend_get_next_symbol(obj);
	}

	// update the new size of the data
	code->size = curr;
	printf("Setting code size to %u\n", code->size);

	// update the relocations to have the new addresses
	return 0;
}

static backend_symbol* get_data_section_symbol(backend_object* obj, unsigned long val)
{
	char name[14];

	// which data segment does this address belong to?
	backend_section* sec = backend_get_first_section(obj);
	while (sec)
	{
		if (val >= sec->address && val < sec->address + sec->size)
		{
			printf("Address 0x%lx is in section %s\n", val, sec->name);

			// should rely on flags, not section name
			if (sec->flags & SECTION_FLAG_INIT_DATA)
				printf("Section %s has init data\n", sec->name);
			else if (sec->flags & SECTION_FLAG_UNINIT_DATA)
				printf("Section %s has uninit data\n", sec->name);
			else
			{
				printf("Section %s is not a data section\n", sec->name);
				break;
			}
			
			// now find the symbol that points to this section
			//printf("Belongs to section %s\n", sec->name);
			backend_symbol *sym = backend_find_symbol_by_name(obj, sec->name);
			if (!sym)
			{
				printf("Creating section symbol %s\n", sec->name);
				sym = backend_add_symbol(obj, sec->name, 0, SYMBOL_TYPE_SECTION, 0, 0, NULL);
			}
			if (!sym)
				return NULL;

			return sym;
		}
		sec = backend_get_next_section(obj);
	}

	return NULL;
}

// Iterate through all the code to find instructions that reference absolute memory. These addresses
// are likely to be variables in the data segment or addresses of called functions. For each one of
// these, we want to replace the absolute value with 0, and create a relocation in its place which
// points to a symbol. Some relocations may already exist if the symbol was dynamically linked
// (.so, .dll, etc.). In that case, the relocation should have already been updated to point to the
// correct symbol, and we may use it as is. For statically linked functions, we must create a new
// relocation and point it to the correct symbol.
static int build_relocations(backend_object* obj)
{
	backend_section* sec_text;
	backend_section* sec;
	ud_t ud_obj;

	ud_init(&ud_obj);

	printf("Building relocations\n");

   /* find the text section */
   sec_text = backend_get_section_by_name(obj, ".text");
   if (!sec_text)
      return -ERR_NO_TEXT_SECTION;

	// make sure we are using the right decoder
	backend_type t = backend_get_type(obj);
	if (t == OBJECT_TYPE_ELF32 || t == OBJECT_TYPE_PE32)
		ud_set_mode(&ud_obj, 32); // decode in 32 bit mode
	else if (t == OBJECT_TYPE_ELF64)
		ud_set_mode(&ud_obj, 64);
	else
		return -ERR_BAD_FORMAT;

	unsigned bytes;
	ud_set_input_buffer(&ud_obj, sec_text->data, sec_text->size);
	//printf("Disassembling from 0x%lx to 0x%lx\n", sec_text->address, sec_text->address + sec_text->size);
	while (bytes = ud_disassemble(&ud_obj))
	{
		long val;
		unsigned int* val_ptr=0;
		const struct ud_operand* op;
		enum ud_mnemonic_code mnem;
		mnem = ud_insn_mnemonic(&ud_obj);
		long addr = ud_insn_off(&ud_obj);
		void* ins_data = (void*)ud_insn_ptr(&ud_obj);
		unsigned int offset = addr + 1; // offset of the operand
		backend_symbol *bs=NULL;
		int opcode_size;

		switch (mnem)
		{
  		//402345:	ff 34 85 d0 80 40 00 	pushl  0x4080d0(,%eax,4)

		// loading a data address:  mov instruction with a 32-bit immediate
		case UD_Imov:
  					// 89 35 ac af 40 00    	mov    %esi,0x40afac
  					// 8a 88 40 80 40 00    	mov    0x408040(%eax),%cl
  					// 8b 15 34 80 40 00    	mov    0x408034,%edx
  					// a1 dc ac 40 00       	mov    0x40acdc,%eax
  					// a3 9c af 40 00       	mov    %eax,0x40af9c
  					// b8 98 81 40 00       	mov    $0x408198,%eax
  					// be 98 82 40 00       	mov    $0x408298,%esi
  					// bf a0 af 40 00       	mov    $0x40afa0,%edi
  					// c7 05 ac af 40 00 01 	movl   $0x1,0x40afac
			//printf("Ins: %s (0x%x) len=%i\n", ud_lookup_mnemonic(mnem), *(char*)ins_data & 0xFF, bytes);
			if (bytes == 6 && ((*(char*)ins_data & 0xFF) == 0x89 ||
									(*(char*)ins_data & 0xFF) == 0x8a  ||
									(*(char*)ins_data & 0xFF) == 0x8b))
				val_ptr = (unsigned int*)(ins_data + 2);
			else if (bytes == 5 && (*(char*)ins_data & 0xFF == 0xa1 ||
									*(char*)ins_data & 0xFF == 0xa3  ||
									*(char*)ins_data & 0xFF == 0xb8 ||
									*(char*)ins_data & 0xFF == 0xbe ||
									*(char*)ins_data & 0xFF == 0xbf))
				val_ptr = (unsigned int*)(ins_data + 1);
			else if (bytes == 7 && (*(char*)ins_data & 0xFF == 0xc7))
				val_ptr = (unsigned int*)(ins_data + 2);

			if (val_ptr)
			{
				//printf("val_ptr %p=0x%x\n", val_ptr, *val_ptr);
				sec = backend_find_section_by_val(obj, *val_ptr);
				if (!sec)
					continue;

				//printf("Found mov @ 0x%lx addr:0x%x\n", sec_text->address + addr, *val_ptr); 

				//printf("Address 0x%lx is in section %s\n", val, sec->name);
				if (strcmp(sec->name, ".text") == 0)
				{
					bs = backend_find_symbol_by_val(obj, *val_ptr);
					if (!bs)
						printf("Can't find function 0x%x\n", *val_ptr);
				}
				else
				{
					// make sure this is a data section
					if ((sec->flags & SECTION_FLAG_INIT_DATA) || (sec->flags & SECTION_FLAG_UNINIT_DATA))
					{
						//printf("Section %s has flags 0x%x\n", sec->name, sec->flags);
						bs = backend_find_symbol_by_name(obj, sec->name);
						if (!bs)
						{
							//printf("Creating section symbol %s\n", sec->name);
							bs = backend_add_symbol(obj, sec->name, 0, SYMBOL_TYPE_SECTION, 0, 0, NULL);
						}
					}
				}
				if (bs)
				{
					// add a relocation
					//printf("Creating relocation to %s @ 0x%lx (%li)\n", bs->name, val, val - sec->address);
					backend_add_relocation(obj, offset, RELOC_TYPE_OFFSET, *val_ptr - sec->address, bs);
				}
				else
				{
					printf("can't find section symbol for %s\n", sec->name);
				}
				*val_ptr = 0;
			}
			break;

		case UD_Ijmp:
					// ff 25 98 62 45 00       jmp    *0x456298
					// e8 00 00 00 00          call   33 <fn000020+0x13>
			if (bytes == 6 && ((*(char*)ins_data & 0xFF) == 0xFF)) 
			{
				val_ptr = (unsigned int*)(ins_data + 2);
				val = *val_ptr;
			}
			else if (bytes == 5 && ((*(char*)ins_data & 0xFF) == 0xe8))
			{
				// this instruction uses a relative offset, so to get the absolute address, add the:
				// section base address + current instruction offset + length of current instruction + call offset
				val_ptr = (unsigned int*)(ins_data + 1);
				val = sec_text->address + addr + bytes + *val_ptr;
			}
			// fall through

		// callq calls a function with 1 byte opcode and signed 32-bit relative offset
		case UD_Icall:
			//printf("Found call @ 0x%lx to 0x%lx\n", sec_text->address + addr, val); 

			if (val_ptr)
			{
				// now we can look up this absolute address in the symbol table to see which static function is called
				backend_symbol *bs = backend_find_symbol_by_val(obj, val);
				if (bs)
				{
					//printf("Adding static reloc offset=%x sym=%s\n", offset, bs?bs->name:"none");
					backend_add_relocation(obj, offset, RELOC_TYPE_PC_RELATIVE, -4, bs);
				}
				else
				{
					sec = backend_find_section_by_val(obj, val);
					if (sec)
					{
						//printf("Address 0x%lx is in section %s\n", val, sec->name);

						bs = backend_find_import_by_address(obj, val);
						if (bs)
						{
							printf("Found import symbol %s\n", bs->name);
							bs = backend_find_symbol_by_name(obj, bs->name);
							if (bs)
							{
								printf("Adding reloc for %s\n", bs->name);
								backend_add_relocation(obj, offset, RELOC_TYPE_PC_RELATIVE, -4, bs);
							}
						}
					}
				}
				*val_ptr = 0;
			}

			break;
		}
	}

	printf("Done building relocations\n");
}

backend_object* set_up_output_file(backend_object* src, const char* filename, backend_type t)
{
	backend_object* oo = backend_create();
	if (!oo)
		return NULL;

	printf("=== Opening file %s\n", filename);
	backend_set_type(oo, t);

	// add a symbol representing the file
	backend_add_symbol(oo, filename, 0, SYMBOL_TYPE_FILE, 0, 0, NULL);

	return oo;
}

// We set up relocations in the source file when it is read in, since that is when we have all of the
// relevant information available. Once the symbols & code are divided into separate object files, it
// is much harder to reconcile jumps between various files since the base addresses are all reset to
// 0. That means when we write out the individual object files, we must copy any relevant relocation
// information that was set up in the input file.
static int copy_relocations(backend_object* src, backend_object* dest)
{
	backend_symbol *sym;
	backend_section* sec;
	int first_function_offset = -1;
 
	printf("Copy relocations - src has %u\n", backend_relocation_count(src));

	if (check_function_sequence(dest) != 0)
	{
		printf("Non-linearity detected in function sequence\n");
		return -1;
	}

	// find the first function, and remember its offset
	sym = backend_get_first_symbol(dest);
	while (sym)
	{
		if (sym->type == SYMBOL_TYPE_FUNCTION)
		{
			first_function_offset = sym->val;
			break;
		}
		sym = backend_get_next_symbol(dest);
	}

	if (first_function_offset == -1)
	{
		printf("No functions found in this output file - no need to copy relocations\n");
		return 0;
	}

	// copy the relocations to the output object, and match the symbols to the output symbol table
	backend_reloc* r = backend_get_first_reloc(src);
	while (r)
	{
		//printf("Checking reloc offset=%lx sym=%s\n", r->offset, r->symbol?r->symbol->name:"none");
		if (!r->symbol)
		{
			//printf("can't find symbol in source file - skipping relocation\n");
			sym = NULL;
			r = backend_get_next_reloc(src);
			continue;
		}

		if (r->offset < first_function_offset)
		{
			//printf("Before first code - skipping relocation\n");
			sym = NULL;
			r = backend_get_next_reloc(src);
			continue;
		}

		switch (r->symbol->type)
		{
		case SYMBOL_TYPE_FUNCTION:
			// if this symbol doesn't exist in the output file, we don't need the relocation information for it
			printf("Looking for symbol %s\n", r->symbol->name);
			sym = backend_find_symbol_by_name(dest, r->symbol->name);
			if (sym)
			{
				//printf("Adding relocation to symbol %s\n", sym->name);
				backend_add_relocation(dest, r->offset - first_function_offset, r->type, r->addend, sym);
			}
			else
				printf("Can't find symbol %s in output file\n", r->symbol->name);
			break;

		case SYMBOL_TYPE_OBJECT:
			if (r->offset < first_function_offset)
				break;

			//printf("Input file has a data relocation to %s\n", r->symbol->name);
			// if we have a data relocation, we must copy the associated symbol as well
			sec = backend_get_section_by_name(dest, r->symbol->section->name);
			if (!sec)
			{
				//printf("Can't get output section %s\n", r->symbol->section->name);
         	sec = backend_add_section(dest, r->symbol->section->name, 0, r->symbol->section->address, NULL, 0, r->symbol->section->alignment, r->symbol->section->flags);
			}
			sym = backend_find_symbol_by_name(dest, r->symbol->name);
			if (!sym)
				printf("Can't find output symbol\n");
			if (sec && !sym)
			{
				//printf("Adding symbol %s\n", r->symbol->name);
				sym = backend_add_symbol(dest, r->symbol->name, r->symbol->val-r->symbol->section->address, r->symbol->type, r->symbol->size, r->symbol->flags, sec);
			}
			if (sym)
			{
				//printf("adding relocation @ 0x%lx - 0x%lx\n", r->offset, r->symbol->section->address);
				backend_add_relocation(dest, r->offset - first_function_offset, r->type, r->addend, sym);
			}
			break;

		case SYMBOL_TYPE_SECTION:
			//printf("Relocation with a section symbol %s found\n", r->symbol->name);

			// add it if its not already there
			sym = backend_find_symbol_by_name(dest, r->symbol->name);
			if (!sym)
				sym = backend_add_symbol(dest, r->symbol->name, r->symbol->val, r->symbol->type, r->symbol->size, r->symbol->flags, sec);
			backend_add_relocation(dest, r->offset - first_function_offset, r->type, r->addend, sym);

			// make sure the output file has the section associated with the symbol as well. Its enough
			// to make sure it exists - the contents will be copied later (in copy_data)
			//printf("Looking for the section\n");
			sec = backend_get_section_by_name(dest, r->symbol->name);
			if (!sec)
			{
			//	printf("Can't find output section %s - adding\n", r->symbol->name);
         	sec = backend_add_section(dest, r->symbol->name, 0, 0, NULL, 0, 1, 0);
			}
			break;
		}

		r = backend_get_next_reloc(src);
	}

	printf("Output file has %u relocations\n", backend_relocation_count(dest));
	return 0;
}

static int copy_data(backend_object* src, backend_object* dest)
{
	// without serious code analysis I can't know how much data to copy. It's because data symbols
	// don't have a size. So for now, I will just copy everything we have to every output object. This
	// will include extraneous information, but it will work.

	backend_section* outsec;
	backend_section* insec = backend_get_first_section(src);
	while (insec)
	{
		// if this is a data section, copy the contents to the output section of the same name
		if (insec->flags & SECTION_FLAG_INIT_DATA || insec->flags & SECTION_FLAG_UNINIT_DATA)
		{
			// if we can't find a matching output section, skip the data
			outsec = backend_get_section_by_name(dest, insec->name);
			if (!outsec)
			{
				//printf("Can't find output section named %s\n", insec->name);
				goto next;
			}

			outsec->data = malloc(insec->size);
			outsec->size = insec->size;
			memcpy(outsec->data, insec->data, insec->size);
		}
next:
		insec = backend_get_next_section(src);
	}

	return 0;
}

static int
unlink_file(const char* input_filename, backend_type output_target)
{
   backend_object* obj = backend_read(input_filename);

	if (!obj)
		return -ERR_BAD_FORMAT;

	// check for symbols, and rebuild if necessary
	if (backend_symbol_count(obj) == 0 && config.reconstruct_symbols == 0)
		return -ERR_NO_SYMS;
	else if (config.reconstruct_symbols)
	{
		reconstruct_symbols(obj, 1);
		if (backend_symbol_count(obj) == 0)
			return -ERR_NO_SYMS_AFTER_RECONSTRUCT;
	}

	// convert any absolute addresses into symbols (loads of data, calls of functions, etc.)
	// make sure any relative jumps are still accurate
	int ret = build_relocations(obj);
	if (ret < 0)
	{
		printf("Can't build relocations: %i\n", ret);
		if (ret == -ERR_BAD_FORMAT)
			printf("Unknown code type!\n");
	}

   // if the output target is not specified, use the input target
	if (output_target == OBJECT_TYPE_NONE)
	{
		output_target = backend_get_type(obj);
		//printf("Setting output type to match input: %i\n", output_target);
	}

	// sort the symbol table after reconstruction and building relocations
	backend_sort_symbols(obj);

   // get the filenames from the input symbol table
   /* iterate over all symbols in the input table */
	backend_section* sec_text = NULL;
	backend_section* sec = NULL;
   backend_object* oo = NULL;
   backend_symbol* sym = backend_get_first_symbol(obj);
   char output_filename[24]; // why is this set to 24??
	unsigned int sec_index=1;
   while (sym)
   {
      // start by finding a file symbol
      int len;
		unsigned int flags=SYMBOL_FLAG_GLOBAL; // mark all functions as global
		unsigned int type=SYMBOL_TYPE_FUNCTION;
		unsigned long base=0;	// base address to remove from symbol values
      switch (sym->type)
      {
      case SYMBOL_TYPE_FILE:
         // if the symbol name ends in .c open a corresponding .o for it
         //printf("File name: %s\n", sym->name);
         len = strlen(sym->name);
         if (sym->name[len-2] != '.' || sym->name[len-1] != 'c')
         {
            sym = backend_get_next_symbol(obj);
            continue;
         }

			// I have seen the case where the same filename was present more than once (consecutively)
         if (strncmp(sym->name, output_filename, strlen(output_filename)-2) == 0)
				break;

			// I have also seen "ghost" files with no name, for no apparent reason
			if (strlen(sym->name) == 0)
				break;

         // close previous file by writing data, if the filenames don't match
         if (oo)
         {
            //printf("Closing existing file %s\n", output_filename);
				copy_relocations(obj, oo);
				fixup_function_data(oo);
				copy_data(obj, oo);
				//backend_sort_symbols(oo);
            if (backend_write(oo, output_filename))
					printf("error writing file\n");
            backend_destructor(oo);
            oo = NULL;
				sec_text = NULL;
         }

         // start a new one
         strcpy(output_filename, sym->name);
         output_filename[len-1] = 'o';
			oo = set_up_output_file(obj, output_filename, output_target);
         if (!oo)
            return -ERR_CANT_CREATE_OO;
         break;

      case SYMBOL_TYPE_SECTION:
         // create the sections and copy the symbols
/*
         printf("Got section %s\n", sym->name);
         sec = backend_get_section_by_name(obj, sym->name);
			if (!sec)
				printf("can't find matching input section\n");
         printf("Found matching input section %s 0x%x\n", sec->name, sec->address);
         sec = backend_add_section(oo, sec->name, 0, sec->address, NULL, 0, sec->alignment, sec->flags);
			if (!sec)
				printf("Error adding section\n");
			backend_add_symbol(oo, sec->name, 0, SYMBOL_TYPE_SECTION, 0, 0, sec);
			printf("done\n");
*/
         break;

      case SYMBOL_TYPE_FUNCTION:
			//printf("Got a function symbol\n");

			// skip any external function
			//if (sym->flags & SYMBOL_FLAG_EXTERNAL)
			//{
				//printf("Skipping external func %s\n", sym->name);
			//	break;
			//}

			// skip any symbol that starts with an underscore
			if (sym->name[0] == '_')
				break;

			if (sym->section && !sec_text)
         	sec_text = backend_get_section_by_name(oo, ".text");

			if (sym->section && !sec_text)
			{
				unsigned long size=0;
				char* data=NULL;
				//printf("no text section found - creating\n");
				//printf("Symbol %s points to section %s (%i)\n", sym->name, sym->section->name, sym->section->size);

				// copy the code to the output object
				size = sym->section->size;
				data = malloc(size);
				memcpy(data, sym->section->data, size);
				//printf("Data: %02x %02x %02x %02x\n", data[0]&0xFF, data[1]&0xFF, data[2]&0xFF, data[3]&0xFF);
        		sec_text = backend_add_section(oo, ".text", size, 0, data, 0, 2, SECTION_FLAG_CODE);
			}

			// set the base address of functions to 0
			if (sym->section)
			{
				//printf("Symbol %s is in section %s\n", sym->name, sym->section->name);
				base = sym->section->address;
			}

         //printf("Found function %s @ 0x%lx + 0x%lx (size:%lu)\n", sym->name, base, sym->val-base, sym->size);

			// any function with a 0 size is probably an external function (from a library)
			// even though it is a function, it should be marked as "No type"
			if (sym->size == 0)
			{
				flags |= SYMBOL_FLAG_GLOBAL | SYMBOL_FLAG_EXTERNAL;
				type = SYMBOL_TYPE_NONE;
			}

			// make sure there is an output file object to add the symbol to
			if (!oo)
			{
				strcpy(output_filename, DEFAULT_OUTPUT_FILENAME);
				oo = set_up_output_file(obj, output_filename, output_target);
				if (!oo)
					return -ERR_CANT_CREATE_OO;
			}

         // add function symbols to the output symbol table
			if (!backend_add_symbol(oo, sym->name, sym->val-base, type, sym->size, flags, sec_text))
				printf("Error while adding symbol %s\n", sym->name);
         break;
      }
   
      sym = backend_get_next_symbol(obj);
   }

   // write data to file
   if (oo)
   {
   	//printf("Writing file %s\n", output_filename);
		copy_relocations(obj, oo);
		fixup_function_data(oo);
		copy_data(obj, oo);
		//backend_sort_symbols(oo);
      if (backend_write(oo, output_filename))
			printf("Error writing file\n");
      backend_destructor(oo);
      oo = NULL;
   }
}

int
main (int argc, char *argv[])
{
   int status = 0;
   char *input_filename = NULL;
   char *output_target = NULL;

	// we have to initialize the backends early so we can print out the names in usage()
   backend_init();

   if (argc < 2)
   {
      usage();
      return -1;
   }

   int c;
   while (1)
   {
      c = getopt_long (argc, argv, "O:R", options, 0);
      if (c == -1)
      break;

      switch (c)
      {
      case 'O':
         output_target = optarg;
         break;

      case 'R':
         config.reconstruct_symbols = 1;
         break;

      default:
         usage();
         return -1;
      }
   }

   if (argc <= optind)
   {
      printf("Missing input file name\n");
      usage();
      return -1;
   }

   input_filename = argv[optind];

   int ret = unlink_file(input_filename, backend_lookup_target(output_target));
   switch (ret)
   {
   case -ERR_BAD_FILE:
      printf("Can't open input file %s\n", input_filename);
      break;
   case -ERR_BAD_FORMAT:
      printf("Unhandled input file format\n");
      break;
   case -ERR_NO_SYMS:
      printf("No symbols found - try again with --reconstruct-symbols\n");
      break;
   case -ERR_NO_SYMS_AFTER_RECONSTRUCT:
      printf("No symbols found even after attempting to recreate them - maybe the code section is empty?\n");
      break;
   case -ERR_NO_TEXT_SECTION:
      printf("Can't find .text section!\n");
      break;
   }

   return status;
}
