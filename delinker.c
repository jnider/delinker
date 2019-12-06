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
#include "config.h"

extern int nucleus_reconstruct_symbols(backend_object *obj);

#define DEFAULT_OUTPUT_FILENAME "default.o"
#define SYMBOL_NAME_MAIN "main"
#define MAX_FILENAME_LENGTH 31

typedef void (reloc_fn)(backend_object* obj, backend_section* sec, csh cs_dis, cs_insn *cs_ins);

// this must be synchronized with "error_code_str" string table,
// because these defines are used as a direct index into the table
enum error_codes
{
   ERR_NONE,
   ERR_BAD_FILE,
   ERR_BAD_FORMAT,
   ERR_NO_SYMS,
   ERR_NO_SYMS_AFTER_RECONSTRUCT,
   ERR_NO_SECTION,
   ERR_NO_TEXT_SECTION,
   ERR_NO_PLT_SECTION,
	ERR_CANT_CREATE_OO,
	ERR_CANT_WRITE_OO,
	ERR_UNSUPPORTED_ARCH,
	ERR_CANT_DISASSEMBLE,
   ERR_NO_MEMORY,
};

typedef char error_msg[32];
error_msg error_code_str[] =
{
   "Success",
   "Bad file",
   "Bad format",
   "No symbols",
   "No symbols after reconstruction",
	"No valid section",
   "No .text section",
   "No PLT section",
   "Can't create output file",
	"Can't write output file",
   "Unsupported architecture",
   "Can't disassemble",
   "Out of memory",
};

static struct option options[] =
{
  {"output-target", required_argument, 0, 'O'},
  {"reconstruct-symbols", no_argument, 0, 'R'},
  {"symbol-per-file", no_argument, 0, 'S'},
  {"verbose", no_argument, 0, 'v'},
  {0, no_argument, 0, 0}
};

// The global configuration options
struct config config;

static void
usage(void)
{
   fprintf(stderr, "Delinker performs the opposite action to 'ld'. It accepts a binary executable as input, and\n");
   fprintf(stderr, "creates a set of .o files that can be relinked.\n\n");
   fprintf(stderr, "delinker [OPTIONS] <input file>\n\n");
   fprintf(stderr, "OPTIONS:\n");
   fprintf(stderr, "-R, --reconstruct-symbols\tRebuild the symbol table by various techniques\n");
   fprintf(stderr, "-S, --symbol-per-file\tCreate a separate .o file for each function\n");
   fprintf(stderr, "-O, --output-target\t\tSpecify the output file format (see supported backend targets below)\n");
   fprintf(stderr, "-v, --verbose\t\t\tPrint lots of information - useful for debugging\n");
   fprintf(stderr, "\nSupported backend targets:\n");
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
	csh cs_dis;
	cs_mode cs_mode;
	cs_insn *cs_ins;
	uint64_t pc_addr;
	const uint8_t *pc;
	size_t n;
	unsigned long prev_addr;

	printf("reconstructing symbols from text section\n");
   /* find the text section */
   backend_section* sec_text = backend_get_section_by_name(obj, ".text");
   if (!sec_text)
      return -ERR_NO_TEXT_SECTION;

	// add a fake symbol for the filename
	backend_add_symbol(obj, "source.c", 0, SYMBOL_TYPE_FILE, 0, 0, sec_text);

	unsigned int start_count = backend_symbol_count(obj);
	printf("Starting with %u symbols\n", start_count);

	// decode (disassemble) the executable section, and assume that any instruction following a 'ret'
   // is the beginning of a new function. Create a symbol entry at that address, and add it to the list.
	// We must also handle 'jmp' instructions in the middle of nowhere (jump tables?) in the same way.
	char name[24];
	unsigned int length;
	int eof = 0;
	size_t ins_count, j;

	prev_addr = sec_text->address;
	sprintf(name, "fn%06X", 0);

	// make sure we are using the right decoder
	backend_type t = backend_get_type(obj);
	if (t == OBJECT_TYPE_ELF32 || t == OBJECT_TYPE_PE32)
		cs_mode = CS_MODE_32;
	else if (t == OBJECT_TYPE_ELF64)
		cs_mode = CS_MODE_64;
	else
		return -ERR_BAD_FORMAT;
	cs_arch arch = CS_ARCH_X86;

	if (cs_open(arch, cs_mode, &cs_dis) != CS_ERR_OK)
		return -1;

	pc = sec_text->data;
	n = sec_text->size;
	pc_addr = sec_text->address;
	cs_ins = cs_malloc(cs_dis);
	if(!cs_ins)
	{
		printf("out of memory");
		return -1;
	}

	while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins))
	{
		// did we hit the official end of the function?
		if (cs_ins->id == X86_INS_IRET || cs_ins->id == X86_INS_JMP)
		{
			eof = 1;
			//printf("end: 0x%lx: %s\n", cs_ins->address, cs_ins->mnemonic);

			// ignore any extraneous bytes after the 'ret' instruction
			if (!padding)
				backend_add_symbol(obj, name, cs_ins->address, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr, SYMBOL_FLAG_GLOBAL, sec_text);
			continue;
		}

		// the next 'valid' instruction starts the next function
		if (eof)
		{
			if (cs_ins->id == X86_INS_INT3 || cs_ins->id == X86_INS_NOP)
				continue;
			else
			{
				// the first instruction after the end of a function - start a new function, and add
				// the previous one to the list
				eof = 0;
				//printf("Start: 0x%lx: %s\n", cs_ins->address, cs_ins->mnemonic);

				if (padding)
					backend_add_symbol(obj, name, prev_addr, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr, SYMBOL_FLAG_GLOBAL, sec_text);

				sprintf(name, "fn%06lX", cs_ins->address);
				prev_addr = cs_ins->address;
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

	printf("%u symbols after reconstruction\n", backend_symbol_count(obj) - start_count);
	cs_free(cs_ins, 1);
	cs_close(&cs_dis);

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

int create_reloc(backend_object *obj, unsigned int val, int offset)
{
	backend_symbol *bs=NULL;
	backend_section* sec;
	static int data_symbols;

	// First, find the section that this symbol belongs in
	sec = backend_find_section_by_val(obj, val);
	if (!sec)
	{
		printf("Doesn't seem to have a containing section\n");
		return -2;
	}

	// Check to see if this is a known symbol
	printf("Looking for symbol @ 0x%x\n", val);
	bs = backend_find_symbol_by_val(obj, val);
	if (bs)
	{
		// add a relocation
		printf("Creating relocation to %s @ 0x%x\n", bs->name, offset);
		return backend_add_relocation(obj, 1, RELOC_TYPE_OFFSET, offset, bs);
	}
	else
	{
		printf("No known symbol for 0x%x but it is in section %s\n", val, sec->name);

		// JKN: we should not be relying on the section name. The code section is
		// called .text by convention, but not mandatory. In fact, there may be more than one code section
		if (strcmp(sec->name, ".text") == 0)
		{
			printf("Should have a symbol in .text - bad address or bad instruction??\n");
			return -3;
		}
		else if (strcmp(sec->name, ".plt") == 0)
		{
			// Maybe it has an import symbol
			printf("Checking for import symbol\n");
			bs = backend_find_import_by_address(obj, val);
			if (bs)
			{
				printf("Found import symbol %s\n", bs->name);
				bs = backend_find_symbol_by_name(obj, bs->name);
				if (bs)
				{
					printf("Creating PC_REL relocation to %s @offset 0x%x\n", bs->name, offset);
					return backend_add_relocation(obj, offset, RELOC_TYPE_PC_RELATIVE, -4, bs);
				}
			}
			else
			{
				printf("Missing import symbol - looks bad.\n");
				return -5;
			}
		}
		else if (strcmp(sec->name, ".plt.got") == 0)
		{
			printf("Not sure what to do with .plt.got symbols. They are dynamic but don't have an import??\n");
			return -4;
		}

		printf("Checking for data symbol\n");
		// make sure this is a data section
		if ((sec->flags & SECTION_FLAG_INIT_DATA) || (sec->flags & SECTION_FLAG_UNINIT_DATA))
		{
			char name[6];
			snprintf(name, 6, ".L%i", data_symbols++);
			printf("Adding symbol %s at %lx to section %s\n", name, val - sec->address, sec->name);
			bs = backend_add_symbol(obj, name, val - sec->address, SYMBOL_TYPE_NONE, 0, 0, sec);
			if (bs)
			{
				// add a relocation
				printf("Creating PC_REL relocation to %s @offset 0x%x\n", bs->name, offset);
				return backend_add_relocation(obj, offset, RELOC_TYPE_PC_RELATIVE, -4, bs);
			}
		}
		else
		{
			printf("Ignoring bad instruction\n");
		}
	}

	return -1;
}

void reloc_x86_32(backend_object* obj, backend_section* sec, csh cs_dis, cs_insn *cs_ins)
{
	const uint8_t *pc = sec->data;
	uint64_t pc_addr = sec->address;
	size_t n = sec->size;

	printf("Disassembling from 0x%lx to 0x%lx\n", sec->address, sec->address + sec->size);
	while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins))
	{
		long val;
		unsigned int* val_ptr=0;
		//unsigned int offset = addr + 1; // offset of the operand
		backend_symbol *bs=NULL;
		int opcode_size;

		switch (cs_ins->id)
		{
  		//402345:	ff 34 85 d0 80 40 00 	pushl  0x4080d0(,%eax,4)

		// loading a data address:  mov instruction with a 32-bit immediate
		case X86_INS_MOV:
  					// 89 35 ac af 40 00    	mov    %esi,0x40afac
  					// 8a 88 40 80 40 00    	mov    0x408040(%eax),%cl
  					// 8b 15 34 80 40 00    	mov    0x408034,%edx
  					// a1 dc ac 40 00       	mov    0x40acdc,%eax
  					// a3 9c af 40 00       	mov    %eax,0x40af9c
  					// b8 98 81 40 00       	mov    $0x408198,%eax
  					// be 98 82 40 00       	mov    $0x408298,%esi
  					// bf a0 af 40 00       	mov    $0x40afa0,%edi
  					// c7 05 ac af 40 00 01 	movl   $0x1,0x40afac
			printf("ins: %s@0x%lx (0x%x) len=%i\n", cs_ins->mnemonic, cs_ins->address, cs_ins->bytes[0], cs_ins->size);
			if (cs_ins->size == 6 && (cs_ins->bytes[0] == 0x89 ||
									cs_ins->bytes[0] == 0x8a  ||
									cs_ins->bytes[0] == 0x8b))
				val_ptr = (unsigned int*)(cs_ins->bytes + 2);
			else if (cs_ins->size == 5 && (cs_ins->bytes[0] == 0xa1 ||
									cs_ins->bytes[0] == 0xa3  ||
									cs_ins->bytes[0] == 0xb8 ||
									cs_ins->bytes[0] == 0xbe ||
									cs_ins->bytes[0] == 0xbf))
				val_ptr = (unsigned int*)(cs_ins->bytes + 1);
			else if (cs_ins->size == 7 && (cs_ins->bytes[0] == 0xc7))
				val_ptr = (unsigned int*)(cs_ins->bytes + 2);

			if (val_ptr)
				create_reloc(obj, *val_ptr, cs_ins->address+2);
			break;

		case X86_INS_JMP:
					// ff 25 98 62 45 00       jmp    *0x456298
					// e8 00 00 00 00          call   33 <fn000020+0x13>
			if (cs_ins->size == 6 && (cs_ins->bytes[0] == 0xFF)) 
			{
				val_ptr = (unsigned int*)(cs_ins->bytes + 2);
				val = *val_ptr;
			}
			else if (cs_ins->size == 5 && (cs_ins->bytes[0] == 0xe8))
			{
				// this instruction uses a relative offset, so to get the absolute address, add the:
				// section base address + current instruction offset + length of current instruction + call offset
				val_ptr = (unsigned int*)(cs_ins->bytes + 1);
				val = sec->address + cs_ins->address + cs_ins->size + *val_ptr;
			}
			// fall through

		// callq calls a function with 1 byte opcode and signed 32-bit relative offset
		case X86_INS_CALL:
			//printf("Found call @ 0x%lx to 0x%lx\n", sec_text->address + addr, val); 

			if (val_ptr)
			{
				// now we can look up this absolute address in the symbol table to see which static function is called
				backend_symbol *bs = backend_find_symbol_by_val(obj, val);
				if (bs)
				{
					//printf("Adding static reloc offset=%x sym=%s\n", offset, bs?bs->name:"none");
					backend_add_relocation(obj, 0, RELOC_TYPE_PC_RELATIVE, -4, bs);
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
								backend_add_relocation(obj, 0, RELOC_TYPE_PC_RELATIVE, -4, bs);
							}
						}
					}
				}
				*val_ptr = 0;
			}

			break;
		}
	}
}

static void reloc_x86_64(backend_object* obj, backend_section* sec, csh cs_dis, cs_insn *cs_ins)
{
	const uint8_t *pc = sec->data;
	uint64_t pc_addr = sec->address;
	size_t n = sec->size;

	printf("x86_64: Disassembling from 0x%lx to 0x%lx\n", sec->address, sec->address + sec->size);
	// check to see if there is a symbol at the beginning of the section
/*
	backend_symbol *s = backend_find_symbol_by_val(obj, sec->address);
	if (s)
	{
		printf("Symbol %s\n", s->name);
	}
*/

	while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins))
	{
		unsigned int val=0;
		//unsigned int offset = addr + 1; // offset of the operand
		backend_symbol *bs=NULL;
		int opcode_size;

		//printf("ins: %s@0x%lx (0x%x) len=%i\n", cs_ins->mnemonic, cs_ins->address, cs_ins->bytes[0], cs_ins->size);
		switch (cs_ins->id)
		{
		case X86_INS_LEA:
			// 48 8d 3d 89 0f 00 00 	lea    0xf89(%rip),%rdi
			if (cs_ins->size == 7 && cs_ins->bytes[0] == 0x48 && cs_ins->bytes[1] == 0x8d &&
				(cs_ins->bytes[2] == 0x3d || cs_ins->bytes[2] == 0x35)) // we only want rsi or rdi targets
			{
				//int *val_ptr = (int*)(cs_ins->bytes + 3);
				int *val_ptr = (int*)((char*)pc - cs_ins->size + 3);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				printf("Found LEA rsi/rdi to 0x%x @ 0x%lx\n", val, cs_ins->address);
				if (create_reloc(obj, val, cs_ins->address+3) == 0)
					*val_ptr = 0;
			}
			break;

		case X86_INS_MOV:
			// 48 8b 05 9b 99 5f 00		mov    0x5f999b(%rip),%rax
			// b8 02 00 1f bb				mov    $0xbb1f0002,%eax
			break;

		case X86_INS_CALL:
    		//	e8 d6 fe ff ff       	callq  1030 <printf@plt> 
			// even though e8 is a relative call, it may call into the PLT
			// which needs to be replaced since the PLT may not survive
			if (cs_ins->size == 5 && cs_ins->bytes[0] == 0xe8)
			{
				int *val_ptr = (int*)(cs_ins->bytes + 1);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				printf("Found CALL E8 to 0x%x @ 0x%lx\n", val, cs_ins->address);
				if (create_reloc(obj, val, cs_ins->address+1) == 0)
				{
					val_ptr = (int*)((char*)pc - cs_ins->size + 1);
					*val_ptr = 0;
				}
			}
    		//	ff 15 66 2f 00 00    	callq  *0x2f66(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
			else if (cs_ins->size == 6 && cs_ins->bytes[0] == 0xff)
			{
				//val_ptr = (unsigned int*)(cs_ins->bytes + 2);
				//printf("Found CALL FF to 0x%x\n", *val_ptr);
			}

			// create a relocation for a call instruction
			break;

		//case CALL: // opcode FF
		// break;
		}

	}
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
	csh cs_dis;
	cs_insn *cs_ins;
	cs_mode cs_mode;
	cs_arch cs_arch;
	cs_x86_op *cs_op;
	reloc_fn *rfn;

   if (config.verbose)
	   fprintf(stderr, "Building relocations\n");

	// make sure we are using the right decoder
	backend_type t = backend_get_type(obj);
	if (t == OBJECT_TYPE_ELF32 || t == OBJECT_TYPE_PE32)
		cs_mode = CS_MODE_32;
	else if (t == OBJECT_TYPE_ELF64)
		cs_mode = CS_MODE_64;
	else
		return -ERR_BAD_FORMAT;

   /* find the text sections */
   sec_text = backend_get_section_by_name(obj, ".text"); // do this by flag, not name
   if (!sec_text)
      return -ERR_NO_TEXT_SECTION;
	
	while (sec_text)
	{
		printf("Building relocations for section %s\n", sec_text->name);

		// The architecture selection is inside the while loop because it
		// should read the arch type from the section rather than the object.
		// I don't think any backends support this right now, but with fat binaries
		// starting to appear, it is likely that we will see a single binary
		// file with different code segments for different architectures
		backend_arch be_arch = backend_get_arch(obj);
		switch (be_arch)
		{
		case OBJECT_ARCH_ARM:
			cs_arch = CS_ARCH_ARM;
			break;
		case OBJECT_ARCH_ARM64:
			cs_arch = CS_ARCH_ARM64;
			break;
		case OBJECT_ARCH_X86:
			cs_arch = CS_ARCH_X86;
			break;
		default:
			continue;	// don't know about this architecture
		}

		// pick the correct arch-specific decoder function
		if (cs_arch == CS_ARCH_X86 && cs_mode == CS_MODE_32)
			rfn = reloc_x86_32;
		else if (cs_arch == CS_ARCH_X86 && cs_mode == CS_MODE_64)
			rfn = reloc_x86_64;
		else
			return -ERR_UNSUPPORTED_ARCH;

		if (cs_open(cs_arch, cs_mode, &cs_dis) != CS_ERR_OK)
			return -ERR_CANT_DISASSEMBLE;

		cs_option(cs_dis, CS_OPT_DETAIL, CS_OPT_ON);

		cs_ins = cs_malloc(cs_dis);
		if(!cs_ins)
			return -ERR_NO_MEMORY;

		rfn(obj, sec_text, cs_dis, cs_ins);

		cs_free(cs_ins, 1);
		cs_close(&cs_dis);

		// get the next .text section
   	//sec_text = backend_get_next_section_by_flag(obj, ".text"); // do this by flag, not name
		sec_text = NULL;
	}

  	if (config.verbose)
		fprintf(stderr, "Done building relocations\n");

	return 0;
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

/* check to see if we need this relocation in the output file 
   It depends on if it is covered by a symbol in the src file
	that also exists in the dest file */
static inline int need_reloc(backend_reloc *r, backend_object *src, backend_object *dest)
{
	backend_symbol* besym;
	backend_symbol* sym;

	printf("Looking for a symbol that covers address 0x%lx\n", r->offset);
	besym = backend_find_symbol_by_val(src, r->offset);
	if (besym)
	{
		printf("Address 0x%lx is covered by symbol %s: 0x%lx to 0x%lx\n", r->offset,
			besym->name, besym->val, besym->val + besym->size);

		sym = backend_find_symbol_by_name(dest, besym->name);
		if (!sym)
		{
			printf("Symbol '%s' doesn't exist in output file - skipping reloc\n", besym->name);
			return -1;
		}
	}
	else
	{
		printf("Strange - this relocation doesn't seem to be covered by any symbol in the src file\n");
		return -1;
	}

	return 0;
}

// We set up relocations in the source file when it is read in, since that is when we have all of the
// relevant information available. Once the symbols & code are divided into separate object files, it
// is much harder to reconcile jumps between various files since the base addresses are all reset to
// 0. That means when we write out the individual object files, we must copy any relevant relocation
// information that was set up in the input file.
// Those relocations are relative to the beginning of the section that they belonged to in the original
// file, so those offsets should be updated if any functions move around in the output file.
static int copy_relocations(backend_object* src, backend_object* dest)
{
	backend_symbol *dest_target; // symbol in output file that copied relocation points to
	backend_symbol *target; // symbol that the relocation points to
	backend_section* sec;
	int first_function_offset = -1;
 
	printf("Copying relocations\n");
	printf("Source file has %u relocs\n", backend_relocation_count(src));

	if (check_function_sequence(dest) != 0)
	{
		printf("Non-linearity detected in function sequence\n");
		return -1;
	}

	// copy the relocations to the output object, and match the symbols to the output symbol table
	backend_reloc* r = backend_get_first_reloc(src);
	while (r)
	{
		target = r->symbol;
		printf("Checking reloc @offset=%lx to symbol %s\n", r->offset, target->name);

		// If this relocation isn't covered by a symbol in the output file, we don't need it
		// First, find which symbol the relocation belongs to (not points at) in the source
		// file. Then see if that symbol made it into this output file.
		if (need_reloc(r, src, dest) == 0)
		{
			dest_target = backend_find_symbol_by_name(dest, target->name);
			if (!dest_target)
			{
				backend_section *dest_sec = backend_get_section_by_name(dest, target->section->name);
				if (!dest_sec)
				{
					// Add the missing section and section symbol
					dest_sec = backend_add_section(dest, target->section->name, 0, target->section->address,
						NULL, 0, target->section->alignment, target->section->flags);
					backend_add_symbol(dest, target->name, 0, SYMBOL_TYPE_SECTION, target->size, 0, 0);
				}
				printf("Adding symbol %s to section %s\n", target->name, target->section->name);
				dest_target = backend_add_symbol(dest, target->name, 0, target->type, target->size,
					target->flags, dest_sec);
				if (!dest_target)
				{
					printf("Can't add symbol %s to output file\n", target->name);
					break;
				}
			}

			backend_symbol *besym = backend_find_symbol_by_val(src, r->offset);
			if (besym)
			{
				printf("Using symbol %s: 0x%lx to 0x%lx\n",
					besym->name, besym->val, besym->val + besym->size);
			}

			// calculate the relocation offset from start of symbol (instead of from start of file)
			unsigned int offset = r->offset - besym->val;

			printf("Adding relocation to symbol %s\n", dest_target->name);
			backend_add_relocation(dest, offset, r->type, r->addend, dest_target);
		}

/*
		switch (src_sym->type)
		{
		case SYMBOL_TYPE_FUNCTION:
			break;

		case SYMBOL_TYPE_OBJECT:
			if (r->offset < first_function_offset)
				break;

			printf("Input file has a data relocation to %s\n", r->symbol->name);
			// if we have a data relocation, we must copy the associated symbol as well
			sec = backend_get_section_by_name(dest, src_sym->section->name);
			if (!sec)
			{
				//printf("Can't get output section %s\n", r->symbol->section->name);
         	sec = backend_add_section(dest, src_sym->section->name, 0, src_sym->section->address, NULL, 0, src_sym->section->alignment, src_sym->section->flags);
			}
			sym = backend_find_symbol_by_name(dest, src_sym->name);
			//if (!sym) printf("Can't find output symbol\n");
			if (sec && !sym)
			{
				//printf("Adding symbol %s\n", r->symbol->name);
				sym = backend_add_symbol(dest, src_sym->name, src_sym->val - src_sym->section->address, src_sym->type, src_sym->size, src_sym->flags, sec);
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
*/

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

			outsec->data = (unsigned char*)malloc(insec->size);
			outsec->size = insec->size;
			memcpy(outsec->data, insec->data, insec->size);
		}
next:
		insec = backend_get_next_section(src);
	}

	return 0;
}

// write an object file containing a single symbol
static int write_symbol(backend_object *oo, backend_object *obj, struct backend_symbol *sym, backend_type output_target)
{
	backend_section *sec_text;
	unsigned char *data;
	unsigned int size;
	unsigned int flags=SYMBOL_FLAG_GLOBAL; // mark all functions as global
	unsigned int type=SYMBOL_TYPE_FUNCTION;
	unsigned long base=0;	// base address to remove from symbol values
   int len;

	if (!sym)
		return -ERR_NO_SYMS;

	if (!sym->section)
	{
		printf("WARNING: Symbol %s is missing a source section!\n", sym->name);
		return -ERR_NO_SECTION;
	}

	// copy the code to the output object
	size = sym->section->size;
	data = (unsigned char*)malloc(size);
	memcpy(data, sym->section->data, size);
	sec_text = backend_add_section(oo, ".text", size, 0, data, 0, 2, SECTION_FLAG_CODE);
	base = sym->section->address;
	// any function with a 0 size is probably an external function (from a library)
	// even though it is a function, it should be marked as "No type"
	if (sym->size == 0)
	{
		flags |= SYMBOL_FLAG_EXTERNAL;
		type = SYMBOL_TYPE_NONE;
	}

	// add the function symbol
	sym = backend_add_symbol(oo, sym->name, sym->val-base, sym->type, sym->size, flags, sec_text);

	copy_relocations(obj, oo);
	fixup_function_data(oo);
	copy_data(obj, oo);

	return 0;
}

static int
unlink_file(const char* input_filename, backend_type output_target)
{
	backend_object* obj; 
   backend_object* oo = NULL;
   char output_filename[MAX_FILENAME_LENGTH+1];

	// read the input file into a generic backend structure
   if (config.verbose)
      fprintf(stderr, "Reading input file %s\n", input_filename);
   obj = backend_read(input_filename);
	if (!obj)
		return -ERR_BAD_FORMAT;

	// check for symbols, and rebuild if necessary
	if (backend_symbol_count(obj) == 0 && config.reconstruct_symbols == 0)
		return -ERR_NO_SYMS;
	else if (config.reconstruct_symbols)
	{
      if (config.verbose)
         fprintf(stderr, "Reconstructing symbols with built-in function detector\n");

		//reconstruct_symbols(obj, 1);
		nucleus_reconstruct_symbols(obj);
		if (backend_symbol_count(obj) == 0)
			return -ERR_NO_SYMS_AFTER_RECONSTRUCT;
	}

	// convert any absolute addresses into symbols (loads of data, calls of functions, etc.)
	// make sure any relative jumps are still accurate
	int ret = build_relocations(obj);
	if (ret < 0)
	{
		printf("Can't build relocations: %s (%i)\n", error_code_str[-ret], ret);
      return ret;
	}

   // if the output target is not specified, use the input target
	if (output_target == OBJECT_TYPE_NONE)
	{
		output_target = backend_get_type(obj);
		//printf("Setting output type to match input: %i\n", output_target);
	}

	// Output symbols to .o files
   backend_symbol* sym = backend_get_first_symbol(obj);
   while (sym)
   {
		if (config.symbol_per_file)
		{
			switch (sym->type)
			{
			case SYMBOL_TYPE_FILE:
			case SYMBOL_TYPE_SECTION:
				// file symbols and section symbols are meta-data
				// we must ignore any in the backend, and add our own before writing the file
				break;

			case SYMBOL_TYPE_FUNCTION:
				// don't bother outputting any external (empty) functions
				if (strstr(sym->name, "@@"))
				{
					printf("Skipping external function %s\n", sym->name);
					break;
				}

				// set up output file
				strncpy(output_filename, sym->name, MAX_FILENAME_LENGTH-2); // leave 2 chars for ".o"
				strncat(output_filename, ".o", MAX_FILENAME_LENGTH);
				oo = set_up_output_file(obj, output_filename, output_target);
				if (!oo)
					return -ERR_CANT_CREATE_OO;

				//printf("Writing symbol %s to file %s\n", sym->name, output_filename);
				write_symbol(oo, obj, sym, output_target);

				// close output file
				if (backend_write(oo, output_filename))
				{
					backend_destructor(oo);
					return -ERR_CANT_WRITE_OO;
				}
				backend_destructor(oo);
				oo = NULL;
				break;
			}
		}

      sym = backend_get_next_symbol(obj);
   }

	return 0;
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
      c = getopt_long (argc, argv, "O:RSv", options, 0);
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

		case 'S':
			config.symbol_per_file = true;
			break;

      case 'v':
         config.verbose = 1;
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
