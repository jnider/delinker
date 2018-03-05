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
#include <udis86.h>
#include "backend.h"

enum error_codes
{
   ERR_NONE,
   ERR_BAD_FILE,
   ERR_BAD_FORMAT,
   ERR_NO_SYMS,
   ERR_NO_SYMS_AFTER_RECONSTRUCT,
   ERR_NO_TEXT_SECTION,
   ERR_NO_PLT_SECTION
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
			printf("sym: %s\t\t0x%lx -> 0x%lx\n", sym->name, sym->val, sym->val+sym->size);
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

static int reconstruct_symbols(backend_object* obj)
{
	char name[10];

	printf("reconstructing symbols from text section\n");
   /* find the text section */
   backend_section* sec_text = backend_get_section_by_name(obj, ".text");
   if (!sec_text)
      return -ERR_NO_TEXT_SECTION;

	// add a fake symbol for the filename
	backend_add_symbol(obj, "source.c", 0, SYMBOL_TYPE_FILE, 0, 0, sec_text);

	// decode (disassemble) the executable section, and assume that any instruction following a 'ret'
   // is the beginning of a new function. Create a symbol entry at that address, and add it to the list.
	// We must also handle 'jmp' instructions in the middle of nowhere (jump tables?) in the same way.
	int sawret = 0;
	ud_t ud_obj;

	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 32); // decode in 32 bit mode
	ud_set_input_buffer(&ud_obj, sec_text->data, sec_text->size);
	//ud_set_syntax(&ud_obj, NULL); // #5 no disassemble!
	while (ud_disassemble(&ud_obj))
	{
		enum ud_mnemonic_code mnem;
		mnem = ud_insn_mnemonic(&ud_obj);
		unsigned int addr = ud_insn_off(&ud_obj);
		//printf("* %s\n", ud_insn_hex(&ud_obj));

		if (mnem == UD_Iret)
		{
			sawret = 1;
			continue;
		}

		if (mnem == UD_Ijmp)
		{
			if (sawret)
			{
				sprintf(name, "fn%06X", addr);
				backend_add_symbol(obj, name, addr, SYMBOL_TYPE_FUNCTION, 0, 0, sec_text);
			}
			sawret = 1;
			continue;
		}

		// skip 'null' instructions until we hit the next 'valid' instruction
		if (sawret && mnem != UD_Iint3)
		{
			sawret = 0;
			sprintf(name, "fn%06X", addr);
			backend_add_symbol(obj, name, addr, SYMBOL_TYPE_FUNCTION, 0, 0, sec_text);
		}
	}

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

				printf("Moving function @ 0x%lx to 0x%lx (size %lu)\n", sym->val, sym->val - offset, sym->size);
				printf("memmove %p, %p (size %lu)\n", code->data + sym->val - offset, code->data + sym->val, sym->size);
				memmove(code->data + sym->val - offset, code->data + sym->val, sym->size);
				sym->val -= offset; // update the symbol address
				curr = sym->val + sym->size;
			}
		}
		sym = backend_get_next_symbol(obj);
	}

	// update the new size of the data
	code->size = curr;
	printf("Setting code size to %u\n", code->size);

	// update the relocations to have the new addresses
	return 0;
}

static int decode_plt_entry(backend_object* obj, backend_section* sec_plt, long plt_addr, long* symbol_addr)
{
	ud_t ud_obj;

	ud_init(&ud_obj);

	*symbol_addr = 0;

	// make sure we are using the right decoder
	backend_type t = backend_get_type(obj);
	if (t == OBJECT_TYPE_ELF32 || t == OBJECT_TYPE_PE32)
		ud_set_mode(&ud_obj, 32); // decode in 32 bit mode
	else if (t == OBJECT_TYPE_ELF64)
		ud_set_mode(&ud_obj, 64);

	// find the right entry
	long entry = (plt_addr - sec_plt->address) / 0x10;
	//printf("symbol points to PLT entry %i\n", entry);

	// decode that entry
	enum ud_mnemonic_code mnem;
	unsigned bytes;
	ud_set_input_buffer(&ud_obj, sec_plt->data + (plt_addr - sec_plt->address), 0x10);
	bytes = ud_disassemble(&ud_obj);
	mnem = ud_insn_mnemonic(&ud_obj);
	if (mnem != UD_Ijmp)
	{
		printf("PLT instruction is not jump\n");
		return -1;
	}

	const struct ud_operand* op = ud_insn_opr(&ud_obj, 0);
	if (!op)
		return -2;

	//printf("%lx: %s\n", plt_addr, ud_lookup_mnemonic(mnem));
	//printf("OP: %lx %lx %lx\n", op->lval.sdword, plt_addr, bytes);
	
	*symbol_addr = op->lval.sdword + plt_addr + bytes;
	return 0;
}

static backend_symbol* create_valid_data_symbol(backend_object* obj, unsigned long val)
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
				printf("Not a data section\n");
				break;
			}
			//sprintf(name, "data%08lx", val);
			//printf("Adding symbol %s\n", name);
			//return backend_add_symbol(obj, name, sec->address, SYMBOL_TYPE_OBJECT, 4, SYMBOL_FLAG_GLOBAL, sec);
			
			// now find the symbol that points to this section
			printf("Belongs to section %s\n", sec->name);
			backend_symbol *sym = backend_find_symbol_by_name(obj, sec->name);
			if (!sym)
			{
				printf("Creating section symbol %s\n", sec->name);
				sym = backend_add_symbol(obj, sec->name, 0, SYMBOL_TYPE_SECTION, 0, 0, sec);
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
	ud_t ud_obj;

	ud_init(&ud_obj);

   /* find the text section */
   backend_section* sec_text = backend_get_section_by_name(obj, ".text");
   if (!sec_text)
      return -ERR_NO_TEXT_SECTION;

   backend_section* sec_plt = backend_get_section_by_name(obj, ".plt");
   if (!sec_plt)
      return -ERR_NO_PLT_SECTION;

	// make sure we are using the right decoder
	backend_type t = backend_get_type(obj);
	if (t == OBJECT_TYPE_ELF32 || t == OBJECT_TYPE_PE32)
		ud_set_mode(&ud_obj, 32); // decode in 32 bit mode
	else if (t == OBJECT_TYPE_ELF64)
		ud_set_mode(&ud_obj, 64);

	unsigned bytes;
	ud_set_input_buffer(&ud_obj, sec_text->data, sec_text->size);
	//printf("Disassembling from 0x%lx to 0x%lx\n", sec_text->address, sec_text->address + sec_text->size);
	while (bytes = ud_disassemble(&ud_obj))
	{
		enum ud_mnemonic_code mnem;
		mnem = ud_insn_mnemonic(&ud_obj);
		long addr = ud_insn_off(&ud_obj);
		void* ins_data = (void*)ud_insn_ptr(&ud_obj);
		unsigned int offset = addr + 1; // offset of the operand

		// loading a data address:  mov instruction with a 32-bit immediate
		if (mnem == UD_Imov && bytes == 5)
		{
			const struct ud_operand* op = ud_insn_opr(&ud_obj, 1);
			if (op->type == UD_OP_IMM)
			{
				unsigned int val = op->lval.udword;
				printf("Found mov @ 0x%lx + 0x%lx = 0x%lx addr:0x%x\n", sec_text->address, addr, sec_text->address + addr, val); 

				backend_symbol *bs = backend_find_symbol_by_val(obj, val);
				if (!bs)
				{
					// if the address is valid, create a new symbol for it
					bs = create_valid_data_symbol(obj, val);
					if (!bs)
					{
						printf("Mov: can't resolve symbol @ 0x%x\n", val);
						continue;
					}
				}

				// add a relocation
				printf("Creating relocation to %s @ 0x%x\n", bs->name, val);
				backend_add_relocation(obj, offset, RELOC_TYPE_OFFSET, bs);
				ins_data += 1; // skip the one byte opcode to find the operand
				*(int*)ins_data = 0;
			}
			//printf("ops: %s <- %s\n", ud_lookup_opr_type(ud_insn_opr(&ud_obj, 0)),
			//	ud_lookup_opr_type(ud_insn_opr(&ud_obj, 1)));
		}
		else if (mnem == UD_Ijmp)
		{
			//printf("0x%lx: %s %u\n", addr + sec_text->address, ud_lookup_mnemonic(mnem), bytes);
		}

		// callq calls a function with 1 byte opcode and signed 32-bit relative offset
		else if (mnem == UD_Icall && bytes == 5)
		{
			long val;
			const struct ud_operand* op = ud_insn_opr(&ud_obj, 0);
			//printf("Op type: %s\n", ud_lookup_opr_type(op));
			if (!op || op->type != UD_OP_JIMM)
				continue;

			// this instruction uses a relative offset, so to get the absolute address, add the:
			// section base address + current instruction offset + length of current instruction + call offset
			val = sec_text->address + addr + bytes + op->lval.sdword;
			//printf("Found call @ 0x%lx + 0x%lx = 0x%lx\n", sec_text->address, addr, sec_text->address + addr); 
			//printf("0x%lx: %s %i (%u)\n", addr + sec_text->address, ud_lookup_mnemonic(mnem), op->lval.sdword, bytes);

			// now we can look up this absolute address in the symbol table to see which static function is called
			backend_symbol *bs = backend_find_symbol_by_val(obj, val);
			if (bs)
			{
				printf("Adding static reloc offset=%x sym=%s\n", 0, bs?bs->name:"none");
				backend_add_relocation(obj, offset, RELOC_TYPE_PC_RELATIVE, bs);
			}
			else
			{
				// there is no existing symbol for this address. Maybe this is a dynamic symbol which requires a
				// jump to the PLT? If so, we should already have a relocation for it.
				if (val < sec_plt->address || val >= sec_plt->address + sec_plt->size)
				{
					//printf("Call: address 0x%lx has no existing symbol, and is not in the PLT\n", (unsigned long)val);
					continue;
				}

				// if the address is in the PLT section, we should have entered a reloc for it when the
				// file was loaded (because it's a dynamic symbol, it comes with a reloc). We want to
				// update that reloc with a new base address from the .text section, rather than the
				// .got section.
				if (decode_plt_entry(obj, sec_plt, val, &val) == 0)
				{
					//printf("Address 0x%lx recovered from PLT - looking for a matching symbol\n", val);
					bs = backend_find_symbol_by_val(obj, val);
					if (!bs)
					{
						printf("Fatal: can't find matching symbol in output file\n");
						continue;
					}
					printf("Adding dyn reloc offset=%x sym=%s\n", offset, bs->name);
					backend_add_relocation(obj, offset, RELOC_TYPE_PC_RELATIVE, bs);
				}
			}

			ins_data += 1; // skip the one byte opcode to find the operand
			*(int*)ins_data = 0;
		}

	}
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
		printf("Checking reloc offset=%lx sym=%s\n", r->offset, r->symbol?r->symbol->name:"none");
		if (!r->symbol)
		{
			//printf("can't find symbol in source file - skipping relocation\n");
			sym = NULL;
			r = backend_get_next_reloc(src);
			continue;
		}

		if (r->offset < first_function_offset)
		{
			printf("Before first code - skipping relocation\n");
			sym = NULL;
			r = backend_get_next_reloc(src);
			continue;
		}

		switch (r->symbol->type)
		{
		case SYMBOL_TYPE_FUNCTION:
			// if this symbol doesn't exist in the output file, we don't need the relocation information for it
			sym = backend_find_symbol_by_name(dest, r->symbol->name);
			if (sym)
				backend_add_relocation(dest, r->offset - first_function_offset, r->type, sym);
			break;

		case SYMBOL_TYPE_OBJECT:
			if (r->offset < first_function_offset)
				break;

			printf("Input file has a data relocation to %s\n", r->symbol->name);
			// if we have a data relocation, we must copy the associated symbol as well
			sec = backend_get_section_by_name(dest, r->symbol->section->name);
			if (!sec)
			{
				printf("Can't get output section %s\n", r->symbol->section->name);
         	sec = backend_add_section(dest, r->symbol->section->name, 0, r->symbol->section->address, NULL, 0, r->symbol->section->alignment, r->symbol->section->flags);
			}
			sym = backend_find_symbol_by_name(dest, r->symbol->name);
			if (!sym)
				printf("Can't find output symbol\n");
			if (sec && !sym)
			{
				printf("Adding symbol\n");
				sym = backend_add_symbol(dest, r->symbol->name, r->symbol->val-r->symbol->section->address, r->symbol->type, r->symbol->size, r->symbol->flags, sec);
			}
			if (sym)
			{
				printf("adding relocation @ 0x%lx - 0x%lx\n", r->offset, r->symbol->section->address);
				backend_add_relocation(dest, r->offset - first_function_offset, r->type, sym);
			}
			break;

		case SYMBOL_TYPE_SECTION:
			printf("^^ Section symbol %s found\n", r->symbol->name);
			sym = backend_add_symbol(dest, r->symbol->name, r->symbol->val, r->symbol->type, r->symbol->size, r->symbol->flags, sec);
			backend_add_relocation(dest, r->offset - first_function_offset, r->type, sym);
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
   if (backend_symbol_count(obj) == 0)
   {
      if (config.reconstruct_symbols == 0)
         return -ERR_NO_SYMS;
      else
      {
         reconstruct_symbols(obj);
         if (backend_symbol_count(obj) == 0)
            return -ERR_NO_SYMS_AFTER_RECONSTRUCT;
      }
   }

	// convert any absolute addresses into symbols (loads of data, calls of functions, etc.)
	// make sure any relative jumps are still accurate
	build_relocations(obj);

   // if the output target is not specified, use the input target
	if (output_target == OBJECT_TYPE_NONE)
	{
		output_target = backend_get_type(obj);
		//printf("Setting output type to match input: %i\n", output_target);
	}

   // get the filenames from the input symbol table
   /* iterate over all symbols in the input table */
	backend_section* sec_text = NULL;
	backend_section* bs = NULL;
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
            if (backend_write(oo, output_filename))
					printf("error writing file\n");
            backend_destructor(oo);
            oo = NULL;
				sec_text = NULL;
         }

         // start a new one
         strcpy(output_filename, sym->name);
         output_filename[len-1] = 'o';
         oo = backend_create();
         if (!oo)
            return -10; 
         printf("=== Opening file %s\n", output_filename);
         backend_set_type(oo, output_target);
         break;

      case SYMBOL_TYPE_SECTION:
         // create the sections and copy the symbols
         printf("Got section %s\n", sym->name);
         bs = backend_get_section_by_name(obj, sym->name);
         //printf("Found matching input section\n");
         backend_add_section(oo, bs->name, 0, bs->address, NULL, 0, bs->alignment, bs->flags);
         break;

      case SYMBOL_TYPE_FUNCTION:
			//printf("Got a function symbol\n");

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
				//printf("Symbol %s points to section %s\n", sym->name, sym->section->name);

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

         //printf("Found function %s @ 0x%lx + 0x%lx\n", sym->name, base, sym->val-base);

			// any function with a 0 size is probably an external function (from a library)
			// even though it is a function, it should be marked as "No type"
			if (sym->size == 0)
			{
				flags |= SYMBOL_FLAG_GLOBAL | SYMBOL_FLAG_EXTERNAL;
				type = SYMBOL_TYPE_NONE;
			}

         // set the base address of all instructions referencing memory to 0

         // add function symbols to the output symbol table
			backend_add_symbol(oo, sym->name, sym->val-base, type, sym->size, flags, sec_text);
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

   char c;
   while ((c = getopt_long (argc, argv, "O:R",
          options, (int *) 0)) != EOF)
   {
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
