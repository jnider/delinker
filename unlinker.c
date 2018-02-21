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
   fprintf(stderr, "unlinker <input file>\n");
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
	// ensure the symbols are sorted in ascending load order, and don't have any overlaps  (curr is the absolute address)
	unsigned long curr = 0;

	printf("fixup_function_data %i\n", backend_symbol_count(obj));
   backend_symbol* sym = backend_get_first_symbol(obj);
	while (sym)
	{
		printf("sym: %s\t\t0x%lx -> 0x%lx\n", sym->name, sym->val, sym->val+sym->size);
		if (sym->val < curr)
		{
			printf("Overlap detected @ 0x%lx!\n", sym->val);
			return -1;
		}
		curr = sym->val + sym->size;
      sym = backend_get_next_symbol(obj);
	}

	// find the the .text section (containing code)
	backend_section* code = backend_get_section_by_name(obj, ".text");
	if (!code)
	{
		printf("Can't find .text section\n");
		return -2;
	}

	// now compact the code (curr is the offset)
	curr = 0;
	sym = backend_get_first_symbol(obj);
	while (sym)
	{
		// if a symbol has 0 length, skip it
		if (sym->size && sym->val != curr)
		{
			printf("Moving function @ 0x%lx to 0x%lx\n", sym->val, curr);
			memmove(code->data + curr, code->data + sym->val, sym->size);
			sym->val = curr; // update the symbol address
			curr += sym->size;
		}
		sym = backend_get_next_symbol(obj);
	}

	// update the new size of the data
	printf("Setting code size to %lu\n", curr);
	code->size = curr;

	return 0;
}

static int decode_plt_entry(backend_object* obj, backend_section* sec_plt, int plt_addr, int* symbol_addr)
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
	int entry = (plt_addr - sec_plt->address) / 0x10;
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

		// loading a data address is a mov instruction with a 32-bit immediate
		if (mnem == UD_Imov && bytes == 7)
		{
			//printf("0x%lx: %s %u\n", addr, ud_lookup_mnemonic(mnem), bytes);
			const char* buff = ud_insn_ptr(&ud_obj);
			const struct ud_operand* op = ud_insn_opr(&ud_obj, 1);
			if (op->type == UD_OP_IMM)
			{
				unsigned int val = op->lval.udword;
				//printf("op 1 is immediate 0x%x\n", val);
				backend_symbol *bs = backend_find_symbol_by_val(obj, val);
				if (!bs)
				{
					printf("Mov: can't resolve symbol @ 0x%x\n", val);
					continue;
				}

				// add a relocation
				//printf("Resolves to %s\n", bs->name);
				//backend_add_relocation(obj, val, RELOC_TYPE_OFFSET, bs);
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
			int val;
			const struct ud_operand* op = ud_insn_opr(&ud_obj, 0);
			//printf("Op type: %s\n", ud_lookup_opr_type(op));
			if (!op || op->type != UD_OP_JIMM)
				continue;
			val = addr + sec_text->address + op->lval.sdword + bytes;
			//printf("0x%lx: %s %i (%u)\n", addr + sec_text->address, ud_lookup_mnemonic(mnem), op->lval.sdword, bytes);
			backend_symbol *bs = backend_find_symbol_by_val(obj, val);
			if (!bs)
			{
				if (val < sec_plt->address || val >= sec_plt->address + sec_plt->size)
				{
					printf("Call: can't resolve symbol @ 0x%lx\n", (unsigned long)val);
					continue;
				}

				if (decode_plt_entry(obj, sec_plt, val, &val) == 0)
				{
					//printf("Address 0x%x recovered from PLT - looking for a matching reloc\n", val);
					// now we have to find the symbol name to be able to create a relocation
					backend_reloc* rel = backend_find_reloc_by_val(obj, val);
					if (!rel)
						continue;
					bs = rel->symbol;
					//printf("Found symbol %s in a relocation\n", bs->name);
				}
			}

			backend_add_relocation(obj, val, RELOC_TYPE_PC_RELATIVE, bs);
		}

	}
}

// We set up relocations in the source file when it is read in, since that is when we have all of the relevant
// information available. Once the symbols & code are divided into separate object files, it is much harder to
// reconcile jumps between various files since the base addresses are all reset to 0. That means when we write
// out the individual object files, we must copy any relevant relocation information that was set up in the
// input file.
static int copy_relocations(backend_object* src, backend_object* dest)
{
	backend_symbol *sym;

	// copy the relocations to the output object, and match the symbols to the output symbol table
	backend_reloc* r = backend_get_first_reloc(src);
	while (r)
	{
		if (!r->symbol)
		{
			//printf("can't find symbol in source file - skipping relocation\n");
			sym = NULL;
			r = backend_get_next_reloc(src);
			continue;
		}

		// if this symbol doesn't exist in the output file, we don't need the relocation information for it
		sym = backend_find_symbol_by_name(dest, r->symbol->name);
		if (!sym)
		{
			//printf("can't find symbol %s in output file\n", r->symbol->name);
			r = backend_get_next_reloc(src);
			continue;
		}
		if (!r->symbol->section)
		{
			printf("Input symbol %s doesn't have an associated section\n", r->symbol->name);
			backend_add_relocation(dest, r->addr, r->type, sym);
			r = backend_get_next_reloc(src);
			continue;
		}
		
		//printf("Base address: 0x%lx\n", r->symbol->section->address);
		backend_add_relocation(dest, r->addr - r->symbol->section->address, r->type, sym);
		r = backend_get_next_reloc(src);
	}

	printf("Output file has %u relocations\n", backend_relocation_count(dest));
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
	unsigned long base=0;	// base address to remove from symbol values
   while (sym)
   {
      // start by finding a file symbol
      int len;
		unsigned int flags=SYMBOL_FLAG_GLOBAL; // mark all functions as global
		unsigned int type=SYMBOL_TYPE_FUNCTION;
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
				//fixup_function_data(oo);
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
         //printf("Got section %s\n", sym->name);
         bs = backend_get_section_by_name(obj, sym->name);
         //printf("Found matching input section\n");
         backend_add_section(oo, 0, strdup(bs->name), 0, bs->address, NULL, 0, bs->alignment, bs->flags);
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
        		sec_text = backend_add_section(oo, 0, strdup(".text"), size, 0, data, 0, 2, SECTION_FLAG_CODE);

			}

			// set the base address of functions to 0
			if (sym->section)
				base = sym->section->address;
			else
				base = 0;

			// any function with a 0 size is probably an external function (from a library)
			// even though it is a function, it should be marked as "No type"
			if (sym->size == 0)
			{
				flags |= SYMBOL_FLAG_GLOBAL | SYMBOL_FLAG_EXTERNAL;
				type = SYMBOL_TYPE_NONE;
			}

         printf("Found function %s @ 0x%lx + 0x%lx\n", sym->name, base, sym->val-base);
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
		//fixup_function_data(oo);
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

   backend_init();

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
