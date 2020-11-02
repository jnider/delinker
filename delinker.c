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

#ifdef DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT //
#endif

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
  {"ignore", required_argument, 0, 'I'},
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
		// Only look at local functions (not imports)
		if (sym->type == SYMBOL_TYPE_FUNCTION && !(sym->flags & SYMBOL_FLAG_EXTERNAL))
		{
			//printf("func: %s\t\t0x%lx -> 0x%lx (flags=0x%x)\n", sym->name, sym->val, sym->val+sym->size, sym->flags);
			if (sym->val < curr)
			{
				printf("Overlap detected @ 0x%lx (curr: 0x%lx)!\n", sym->val, curr);
				return -1;
			}
			curr = sym->val + sym->size;
		}
      sym = backend_get_next_symbol(obj);
	}

	return 0;
}

static int reconstruct_symbols_x86_64(csh cs_dis, cs_insn *cs_ins, backend_object *obj, backend_section *sec_text, const char *src_name)
{
	uint64_t pc_addr;
	const uint8_t *pc;
	size_t length;
	unsigned long prev_addr = 0;
	char name[24];

	DEBUG_PRINT("Reconstructing x86_64 symbols\n");
	pc = sec_text->data;
	length = sec_text->size;
	pc_addr = sec_text->address;
	while(cs_disasm_iter(cs_dis, &pc, &length, &pc_addr, cs_ins))
	{
		// In x86_64, any ENDBR64 instruction by definition is the target of a branch, and should have a symbol associated with it
		if (cs_ins->id == X86_INS_ENDBR64)
		{
			if (prev_addr)
			{
				sprintf(name, "fn%06lX", prev_addr);
				backend_symbol *s = backend_add_symbol(obj, name, prev_addr, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr, SYMBOL_FLAG_GLOBAL, sec_text);
				backend_set_source_file(s, src_name);
			}

			DEBUG_PRINT("Starting symbol @ 0x%lx\n", cs_ins->address);
			prev_addr = cs_ins->address;
		}
	}

	if (prev_addr)
	{
		sprintf(name, "fn%06lX", prev_addr);
		backend_symbol *s = backend_add_symbol(obj, name, prev_addr, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr, SYMBOL_FLAG_GLOBAL, sec_text);
		backend_set_source_file(s, src_name);
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
	const char fake_src_name[] = "source.c";

	printf("reconstructing symbols from text section\n");
   /* find the text section */
   backend_section* sec_text = backend_get_section_by_name(obj, ".text");
   if (!sec_text)
      return -ERR_NO_TEXT_SECTION;

	// add a fake symbol for the filename
	backend_add_symbol(obj, fake_src_name, 0, SYMBOL_TYPE_FILE, 0, 0, sec_text);

	unsigned int start_count = backend_symbol_count(obj);
	DEBUG_PRINT("Starting with %u symbols\n", start_count);

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

	if (t == OBJECT_TYPE_ELF64 && arch == CS_ARCH_X86)
		reconstruct_symbols_x86_64(cs_dis, cs_ins, obj, sec_text, fake_src_name);
	else
	while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins))
	{
		// did we hit the official end of the function?
		if (cs_ins->id == X86_INS_IRET || cs_ins->id == X86_INS_JMP)
		{
			eof = 1;
			//printf("end: 0x%lx: %s\n", cs_ins->address, cs_ins->mnemonic);

			// ignore any extraneous bytes after the 'ret' instruction
			if (!padding)
			{
				sprintf(name, "fn%06lX", prev_addr);
				backend_add_symbol(obj, name, prev_addr, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr, SYMBOL_FLAG_GLOBAL, sec_text);
			}
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
				{
					sprintf(name, "fn%06lX", prev_addr);
					backend_add_symbol(obj, name, prev_addr, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr, SYMBOL_FLAG_GLOBAL, sec_text);
				}

				prev_addr = cs_ins->address;
			}
		}
	}

	// if we hit the end of the section add the last symbol
	if (eof && padding)
	{
		sprintf(name, "fn%06lX", prev_addr);
		backend_add_symbol(obj, name, prev_addr, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr, SYMBOL_FLAG_GLOBAL, sec_text);
	}

	// If we have reconstructed symbols and we want to be able to link again later, the linker is going to
	// look for a symbol called 'main'. We must rename the symbol at the original entry point to be called main.
	// This is practically the only symbol that we can recover the name for without major decompiling efforts.
	backend_symbol *bs = backend_find_symbol_by_val_type(obj, backend_get_entry_point(obj), SYMBOL_TYPE_FUNCTION);
	if (bs)
	{
		DEBUG_PRINT("found entry point %s @ 0x%lx - renaming to 'main'\n", bs->name, bs->val);
		free(bs->name);
		bs->name = strdup(SYMBOL_NAME_MAIN);
	}
	else
	{
		printf("No symbol for entry point @ 0x%lx - the recovery is not very accurate\n", backend_get_entry_point(obj));
		//bs = backend_find_nearest_symbol(obj, backend_get_entry_point(obj));
		//printf("%s @ 0x%lx is the closest - splitting\n", bs->name, bs->val);
		// This crashes sometimes - and is probably not a good idea anyway
      //backend_split_symbol(obj, bs, SYMBOL_NAME_MAIN, backend_get_entry_point(obj), SYMBOL_TYPE_FUNCTION, 0);
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

	printf(".text section base = 0x%lx\n", code->address);
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
			{
				printf("Error adding sec symbol %s\n", sec->name);
				return NULL;
			}

			return sym;
		}
		sec = backend_get_next_section(obj);
	}

	return NULL;
}

int create_reloc(backend_object *obj, backend_reloc_type t, unsigned int val, int offset)
{
	backend_symbol *bs=NULL;
	backend_section* sec;
	static int data_symbols;
	int addend = 0;

	// First, find the section that this symbol belongs in
	sec = backend_find_section_by_val(obj, val);
	if (!sec)
	{
		printf("  Address 0x%x doesn't have a containing section\n", val);
		return -2;
	}

	// Check to see if this is a known symbol
	DEBUG_PRINT("[0x%x]: looking up symbol @ 0x%x - ", offset, val);
	bs = backend_find_symbol_by_val(obj, val);
	if (bs)
	{
		// add a relocation
		DEBUG_PRINT("   Creating (known) relocation to %s @ 0x%x\n", bs->name, offset);
		return backend_add_relocation(obj, offset, t, -4, bs);
	}
	else
	{
		printf("No known symbol for 0x%x but it is in section %s %u\n", val, sec->name, sec->type);

		// symbol must be in a program section (GOT, PLT, data, code)
		if (sec->type != SECTION_TYPE_PROG)
		{
			printf("Symbol is not in a program section - no good\n");
			return -5;
		}

		// Maybe it has an import symbol
		DEBUG_PRINT("Checking for import symbol @ %x\n", val);
		bs = backend_find_import_by_address(obj, val);
		if (bs)
		{
			printf("  Found import symbol %s (flags=%u)\n", bs->name, bs->flags);
			bs = backend_find_symbol_by_name(obj, bs->name);
			if (bs)
			{
				printf("   Creating (PLT) relocation to %s @ 0x%x\n", bs->name, offset);
				return backend_add_relocation(obj, offset, RELOC_TYPE_PLT, -4, bs);
			}
		}
		else if (strcmp(sec->name, ".plt.got") == 0)
		{
			printf("Not sure what to do with .plt.got symbols. They are dynamic but don't have an import??\n");
			return -4;
		}
		else
		{
			printf("Can't find import symbol!\n");
			return -6;
		}

		if ((sec->flags & SECTION_FLAG_INIT_DATA) || (sec->flags & SECTION_FLAG_UNINIT_DATA))
		{
			// get the section symbol related to this section
			int sec_index = backend_get_section_index_by_name(obj, sec->name);
			//printf("Section %s is index %i\n", sec->name, sec_index);
			bs = backend_find_symbol_by_index(obj, sec_index);
			if (bs)
			{
				if (bs->type != SYMBOL_TYPE_SECTION)
					printf("Symbol is not a section symbol!\n");

				// add a relocation
				if (t == RELOC_TYPE_PC_RELATIVE)
				{
					addend = val - sec->address - 4;
					printf("  Creating PC_REL to %s +0x%x\n", bs->name, addend);
					return backend_add_relocation(obj, offset, t, addend, bs);
				}
				else if (t == RELOC_TYPE_OFFSET)
				{
					addend = val - sec->address;
					printf("  Creating REL_OFFSET to %s+%i @offset 0x%x\n", bs->name, addend, offset);
					return backend_add_relocation(obj, offset, t, addend, bs);
				}
				else
					printf("Unknown relocation type: %i\n", t);
			}
			else
			{
				printf("Missing section symbol for %s\n", sec->name);
			}
		}
		else
		{
			// This might be a debug instruction, or just a 'mov' instruction that
			// shouldn't have a relocation at all.
			printf("Ignoring instruction - no reloc\n");
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
		int* val_ptr=0;
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
			if (cs_ins->size == 6 && (cs_ins->bytes[0] == 0x89 ||
									cs_ins->bytes[0] == 0x8a  ||
									cs_ins->bytes[0] == 0x8b))
				val_ptr = (int*)(cs_ins->bytes + 2);
			else if (cs_ins->size == 5 && (cs_ins->bytes[0] == 0xa1 ||
									cs_ins->bytes[0] == 0xa3  ||
									cs_ins->bytes[0] == 0xb8 ||
									cs_ins->bytes[0] == 0xbe ||
									cs_ins->bytes[0] == 0xbf))
				val_ptr = (int*)(cs_ins->bytes + 1);
			else if (cs_ins->size == 7 && (cs_ins->bytes[0] == 0xc7))
				val_ptr = (int*)(cs_ins->bytes + 2);

			if (val_ptr)
			{
				if (create_reloc(obj, RELOC_TYPE_OFFSET, *val_ptr, cs_ins->address+2) == 0)
					*val_ptr = 0;
			}
			break;

		case X86_INS_JMP:
					// ff 25 98 62 45 00       jmp    *0x456298
					// e8 00 00 00 00          call   33 <fn000020+0x13>
					// e9 ae cc ff ff          jmp    8048660 <malloc@plt>
			if (cs_ins->size == 6 && (cs_ins->bytes[0] == 0xFF)) 
			{
				val_ptr = (int*)(cs_ins->bytes + 2);
				val = *val_ptr;
			}
			else if (cs_ins->size == 5 && (cs_ins->bytes[0] == 0xe8 || cs_ins->bytes[0] == 0xe9))
			{
				// this instruction uses a relative offset, so to get the absolute address, add the:
				// current instruction offset + length of current instruction + call offset
				val_ptr = (int*)(cs_ins->bytes + 1);
				val = cs_ins->address + cs_ins->size + *val_ptr;
			}
			if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+1) == 0)
				break;
				//*val_ptr = 0;
			break;

		// callq calls a function with 1 byte opcode and signed 32-bit relative offset
		case X86_INS_CALL:
			//printf("Found call @ 0x%lx to 0x%lx\n", sec_text->address + addr, val); 
			break;
		}
	}
}

static void reloc_x86_64(backend_object* obj, backend_section* sec, csh cs_dis, cs_insn *cs_ins)
{
	const uint8_t *pc = sec->data;
	uint64_t pc_addr = sec->address;
	size_t n = sec->size;

	//printf("x86_64: Disassembling from 0x%lx to 0x%lx\n", sec->address, sec->address + sec->size);

	while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins))
	{
		int val=0;
		//unsigned int offset = addr + 1; // offset of the operand
		backend_symbol *bs=NULL;
		int opcode_size;

		//printf("ins: %s@0x%lx (0x%x) len=%i\n", cs_ins->mnemonic, cs_ins->address, cs_ins->bytes[0], cs_ins->size);
		switch (cs_ins->id)
		{
		case X86_INS_LEA:
			// 48 8d 3d 89 0f 00 00 	lea    0xf89(%rip),%rdi
			if (cs_ins->size == 7 && cs_ins->bytes[0] == 0x48 && cs_ins->bytes[1] == 0x8d &&
				(cs_ins->bytes[2] == 0x3d || cs_ins->bytes[2] == 0x35 || cs_ins->bytes[2] == 0x0d || cs_ins->bytes[2] == 0x05)) // rsi rdi rcx rax
			{
				int *val_ptr = (int*)((char*)pc - cs_ins->size + 3);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+3) == 0)
					*val_ptr = 0;
			}
			break;

		case X86_INS_MOV:
			// 48 8b 05 9b 99 5f 00		mov    0x5f999b(%rip),%rax
			if (cs_ins->size == 7 && cs_ins->bytes[0] == 0x48 && cs_ins->bytes[1] == 0x8b &&
				(cs_ins->bytes[2] == 0x05 || cs_ins->bytes[2] == 0x0d || cs_ins->bytes[2] == 0x15 ||
				cs_ins->bytes[2] == 0x35 || cs_ins->bytes[2] == 0x3d))
			{
				int *val_ptr = (int*)((char*)pc - cs_ins->size + 3);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+3) == 0)
					*val_ptr = 0;
			}
			// 48 89 05 87 39 10 00 	mov    %rax,0x103987(%rip)
			else if (cs_ins->size == 7 && cs_ins->bytes[0] == 0x48 && cs_ins->bytes[1] == 0x89 &&
				(cs_ins->bytes[2] == 0x05 || cs_ins->bytes[2] == 0x0d || cs_ins->bytes[2] == 0x15))
			{
				int *val_ptr = (int*)((char*)pc - cs_ins->size + 3);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+3) == 0)
					*val_ptr = 0;
			}

			// b8 02 00 1f bb				mov    $0xbb1f0002,%eax
			// bf 43 08 40 00       	mov    $0x400843,%edi
			else if (cs_ins->size == 5 && cs_ins->bytes[0] == 0xbf)
			{
				int *val_ptr = (int*)((char*)pc - cs_ins->size + 1);
				val = *val_ptr;
				if (create_reloc(obj, RELOC_TYPE_OFFSET, val, cs_ins->address+1) == 0)
					*val_ptr = 0;
			}
			break;

		case X86_INS_MOVQ:
			//48 c7 05 c9 f7 10 00 01 00 00 00 	movq   $0x1,0x10f7c9(%rip)
			if (cs_ins->size == 11 && cs_ins->bytes[0] == 0x48 && cs_ins->bytes[1] == 0xc7 &&
				(cs_ins->bytes[2] == 0x05))
			{
				int *val_ptr = (int*)((char*)pc - cs_ins->size + 3);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+3) == 0)
					*val_ptr = 0;
			}
			break;

		case X86_INS_CALL:
    		//	e8 d6 fe ff ff       	callq  1030 <printf@plt> 
			// even though e8 is a relative call, it may call into the PLT
			// which needs to be replaced since the PLT may not survive
			if (cs_ins->size == 5 && cs_ins->bytes[0] == 0xe8)
			{
				int *val_ptr = (int*)((char*)pc - cs_ins->size + 1);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				//printf("Found CALL E8 to 0x%x @ 0x%lx\n", val, cs_ins->address);
				if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+1) == 0)
					*val_ptr = 0;
			}
    		//	ff 15 66 2f 00 00    	callq  *0x2f66(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
			else if (cs_ins->size == 6 && cs_ins->bytes[0] == 0xff)
			{
				//val_ptr = (unsigned int*)(cs_ins->bytes + 2);
				//printf("Found CALL FF to 0x%x\n", *val_ptr);
			}

			// create a relocation for a call instruction
			break;

		case X86_INS_VMOVAPD:
			// c5 fd 28 1d f7 3d 00 00		vmovapd 0x3df7(%rip),%ymm3
		case X86_INS_VMOVSD:
			// c5 fb 10 05 71 3d 00 00		vmovsd 0x3d71(%rip),%xmm0
			// c5 fb 11 86 90 c1 ff ff  	vmovsd %xmm0,-0x3e70(%rsi)
                case X86_INS_VMOVDQA:
			// c5 f9 6f 0d f0 16 00 00   vmovdqa 0x16f0(%rip),%xmm1
		case X86_INS_VMULSD:
			// c5 eb 59 3d 7d 2f 00 00 	vmulsd 0x2f7d(%rip),%xmm2,%xmm7
			int *val_ptr = (int*)((char*)pc - cs_ins->size + 4);
			val = cs_ins->address + *val_ptr + cs_ins->size;
			//printf("Found VMOVAPD to 0x%x @ 0x%lx\n", val, cs_ins->address);
			if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+4) == 0)
				*val_ptr = 0;
			break;

		//case CALL: // opcode FF
		// break;
		}

	}
}

// Iterate through all the code to find instructions that reference absolute memory. These addresses
// are likely to be variables in the data segment or addresses of called functions. For each one of
// these, we want to replace the absolute value with 0, and create a relocation in its place which
// points to a symbol. Any existing relocations for dynamically linked symbols are not valid, because
// they only point from the PLT to the GOT (so they are thrown away). New symbols have been added to
// the PLT to represent the target address used in 'call' instructions.
// For each instruction, we must create a new relocation and point it to the correct symbol.
static int build_relocations(backend_object* obj)
{
	backend_section* curr_sec;
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
	//curr_sec = backend_get_first_section(obj);
	curr_sec = backend_get_first_section_by_type(obj, SECTION_TYPE_PROG);
	while (curr_sec)
	{
		// only process executable sections that don't have an entry size
		if (!(curr_sec->flags & SECTION_FLAG_EXECUTE) ||
			curr_sec->entry_size > 0)
		{
			DEBUG_PRINT("Skipping section %s flags 0x%x entry size=%u\n", curr_sec->name, curr_sec->flags, curr_sec->entry_size);
			curr_sec = backend_get_next_section(obj);
			continue;
		}

		printf("Building relocations for section %s\n", curr_sec->name);

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

		rfn(obj, curr_sec, cs_dis, cs_ins);

		cs_free(cs_ins, 1);
		cs_close(&cs_dis);

		// get the next .text section
		curr_sec = backend_get_next_section(obj);
	}

  	if (config.verbose)
		fprintf(stderr, "Done building relocations\n");

	return 0;
}

/* check to see if we need this relocation in the output file 
   It depends on if it is covered by a symbol in the src file
	that also exists in the dest file */
static inline int need_reloc(backend_reloc *r, backend_object *src, backend_object *dest)
{
	backend_symbol* besym;
	backend_symbol* sym;
	unsigned long address = r->offset;

	switch (r->type)
	{
	case RELOC_TYPE_OFFSET:
		address = r->addend;
		break;

	case RELOC_TYPE_PC_RELATIVE:
		address == r->offset;
		break;

	case RELOC_TYPE_PLT:
		address == r->offset;
		break;

	default:
		printf("Unhandled relocation type\n");
		return -1; // I guess we don't need it
	}

	//printf(">>Reloc addend: 0x%lx offset: 0x%lx\n", r->addend, r->offset);
	//printf("Looking for a symbol that covers address 0x%lx\n", address);
	besym = backend_find_symbol_by_val(src, r->offset);
	if (besym)
	{
		//printf("  Address 0x%lx is covered by symbol %s: 0x%lx to 0x%lx\n", address,
		//	besym->name, besym->val, besym->val + besym->size);

		sym = backend_find_symbol_by_name(dest, besym->name);
		if (!sym)
		{
			//printf("  Symbol '%s' doesn't exist in output file - skipping reloc\n", besym->name);
			return -1;
		}
	}
	else
	{
		//printf("Strange - this relocation doesn't seem to be covered by any symbol in the src file\n");
		return -1;
	}

	//printf("Using reloc addend: 0x%lx offset: 0x%lx\n", r->addend, r->offset);
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
 
	printf("=== Copying relocations for %s\n", dest->name);
	//printf("Source file has %u relocs\n", backend_relocation_count(src));

	// why am I doing this here?
/*
	if (check_function_sequence(dest) != 0)
	{
		printf("Non-linearity detected in function sequence\n");
		return -1;
	}
*/

	// copy the relocations to the output object, and match the symbols to the output symbol table
	backend_reloc* r = backend_get_first_reloc(src);
	while (r)
	{
		target = r->symbol;
		//printf("Checking reloc @offset=%lx to symbol %s (flags=%u)\n", r->offset, target->name, target->flags);

		// If this relocation isn't covered by a symbol in the output file, we don't need it
		// First, find which symbol the relocation is contained by (not points at) in the source
		// file. Then see if that symbol made it into this output file.
		if (need_reloc(r, src, dest) == 0)
		{
			// Check to see if the output object already contains a symbol with this name.
			// All (real) symbols belonging to this file should have already been copied,
			// so if a symbol is missing, it must be external and must be added.
			//printf("Copying reloc @offset=%lx to symbol %s\n", r->offset, target->name);
			dest_target = backend_find_symbol_by_name(dest, target->name);
			if (!dest_target)
			{
				backend_section *dest_sec = backend_get_section_by_name(dest, target->section->name);
				if (!dest_sec)
				{
					// Add the missing section and section symbol
					printf("Adding section %s (flags=0x%x)\n", target->section->name, target->section->flags);
					dest_sec = backend_add_section(dest, target->section->name, 0, target->section->address,
						NULL, 0, target->section->alignment, target->section->flags);
				}

				if (target->type == SYMBOL_TYPE_FUNCTION)
				{
					printf("Adding external symbol %s\n", target->name);
					dest_target = backend_add_symbol(dest, target->name, 0, SYMBOL_TYPE_NONE, 0,
						SYMBOL_FLAG_GLOBAL | SYMBOL_FLAG_EXTERNAL, NULL);
					if (!dest_target)
					{
						printf("Error adding external symbol %s to output file %s\n", target->name, dest->name);
						break;
					}
				}
				else
				{
					// Generally, section symbols don't have a name. But there doesn't seem to be
					// any reason why not, and it makes it easier to debug
					dest_target = backend_add_symbol(dest, target->section->name, target->val, SYMBOL_TYPE_SECTION, target->size, 0, dest_sec);
					if (!dest_target)
						printf("Error adding section symbol %s\n", dest_target->name);
				}
			}

			backend_symbol *besym = backend_find_symbol_by_val(src, r->offset);
			if (besym)
			{
				// calculate the relocation offset from start of section
				unsigned int offset = r->offset - besym->section->address;

				printf("Adding relocation to symbol %s (offset=0x%x type=%i)\n", dest_target->name, offset, dest_target->type);
				backend_add_relocation(dest, offset, r->type, r->addend, dest_target);
			}
			else
			{
				printf("can't find src symbol to match value 0x%lx\n", r->offset);
			}
		}
		else
		{
			//printf("Ignoring reloc @offset=%lx to symbol %s (flags=%u)\n", r->offset, target->name, target->flags);
		}

		r = backend_get_next_reloc(src);
	}

#ifdef DEBUG
	printf("Output file has %u relocations\n", backend_relocation_count(dest));
	backend_reloc* tr = backend_get_first_reloc(dest);
	while (tr)
	{
		printf("** Symbol %s (val 0x%lx) Offset: 0x%lx\n", tr->symbol->name, tr->symbol->val, tr->offset);
		tr = backend_get_next_reloc(dest);
	}
#endif // DEBUG

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

			unsigned int old_size = outsec->size;
			outsec->data = (unsigned char*)realloc(outsec->data, old_size + insec->size);
			outsec->size += insec->size;
			if (!(insec->flags & SECTION_FLAG_UNINIT_DATA))
				memcpy(outsec->data + old_size, insec->data, insec->size);
		}
next:
		insec = backend_get_next_section(src);
	}

	return 0;
}

// copy an object (symbol + data) to a backend object
static int write_symbol(backend_object *oo, backend_object *obj, struct backend_symbol *sym, backend_type output_target)
{
	backend_section *sec_out;
	unsigned char *data=0;
	unsigned int size=0;
	unsigned int type=SYMBOL_TYPE_FUNCTION;
	unsigned long base=0;	// base address to remove from symbol values
	unsigned int alignment=1;
	unsigned long offset;
   int len;

	if (!sym)
		return -ERR_NO_SYMS;

	if (!sym->section)
	{
		printf("WARNING: Symbol %s is missing a source section!\n", sym->name);
		return -ERR_NO_SECTION;
	}

	//printf("Writing symbol %s (size=%lu)\n", sym->name, sym->size);

	// calculate base
	base = sym->section->address;
	offset = sym->val - base;
	alignment = sym->section->alignment;

	// we want to include the offset so we can position the object at the original location.
	// That will ensure that the relocations and symbols all line up. We can 'fix up' the
	// pointers after.
	//printf("Symbol @ 0x%lx in section %s @ 0x%lx (offset=0x%lx flags=0x%x align=%u)\n", sym->val,
	//	sym->section->name, sym->section->address, offset, sym->section->flags, sym->section->alignment);

	// make room in the output object
	sec_out = backend_get_section_by_name(oo, sym->section->name);
	if (!sec_out)
	{
		// if the object is not empty, copy it
		if (sym->size)
		{
			// copy the code/data to the output object
			size = sym->size + offset;
			//printf("   allocating %i bytes\n", size);
			data = (unsigned char*)malloc(size);
			if ((sym->section->flags & SECTION_FLAG_UNINIT_DATA) == 0)
			{
				//printf("  copying %lu bytes from offset 0x%lx\n", sym->size, offset);
				//printf("  dest=%p src=%p size=%lu\n", data+offset, sym->section->data+offset, sym->size);
				memcpy(data+offset, sym->section->data+offset, sym->size);
			}
		}

		printf("Adding section %s (flags=0x%x) for symbol %s\n", sym->section->name, sym->section->flags, sym->name);
		sec_out = backend_add_section(oo, sym->section->name, size, 0, data,
			0, sym->section->alignment, sym->section->flags);

		// Generally, section symbols don't have a name. But there doesn't seem to be
		// any reason why not, and it makes it easier to debug
		if (!backend_add_symbol(oo, sec_out->name, 0, SYMBOL_TYPE_SECTION, 0, 0, sec_out))
			printf("Error adding section symbol %s\n", sec_out->name);
	}
	else
	{
		// if the object is not empty, copy it
		if (sym->size)
		{
			//printf("Going to write %lu bytes at offset 0x%lx\n", sym->size, offset);
			if (offset + sym->size > sec_out->size)
			{
				//printf("Buffer is too small (%u need %lu)\n", sec_out->size, offset + sym->size);

				//printf("Output section %s found - extending from %u to %lu\n",
				//	sec_out->name, sec_out->size, sec_out->size + sym->size);
				data = (unsigned char*)realloc(sec_out->data, offset + sym->size);
				if (data)
				{
					sec_out->data = data;
					sec_out->size = offset + sym->size;
				}
				else
				{
					printf("Error realloc\n");
				}
			}
			if ((sym->section->flags & SECTION_FLAG_UNINIT_DATA) == 0)
			{
				//printf("  copying %lu bytes from offset 0x%lx\n", sym->size, offset);
				//printf("  dest=%p src=%p size=%lu\n", sec_out->data+offset, sym->section->data+offset, sym->size);
				memcpy(sec_out->data+offset, sym->section->data+offset, sym->size);
			}
		}
	}

	// add the function symbol
	printf("Adding symbol %s @ 0x%lx (type=%i size=%lu) to %s\n", sym->name, sec_out->address+offset, sym->type, sym->size, oo->name);
	sym = backend_add_symbol(oo, sym->name, sec_out->address+offset, sym->type, sym->size, sym->flags, sec_out);
	if (!sym)
		printf("Error adding symbol\n"); 

	return 0;
}

static int ignore_symbol(backend_symbol *sym)
{
   for (const list_node* iter=ll_iter_start(config.ignore_list); iter != NULL; iter=iter->next)
   {
		char *tmp_name = (char*)iter->val;
		if (strcmp(sym->name, tmp_name) == 0)
			return 1;
	}
	return 0;
}

static int close_output_object(backend_object *oo)
{
	int ret = 0;
	if (config.verbose)
		fprintf(stderr, "Writing file %s\n", oo->name);
	if (backend_write(oo))
		ret = -ERR_CANT_WRITE_OO;
	backend_destructor(oo);
	return ret;
}

static void finalize_objects(linked_list *oo_list, backend_object *src)
{
	// iterate through each object from the list
   for (const list_node* iter=ll_iter_start(oo_list); iter != NULL; iter=iter->next)
   {
		backend_object *oo = (backend_object*)iter->val;
		copy_relocations(src, oo);

		//printf("Fixup function data\n");
		//fixup_function_data(oo); //this seems like a poorly written optimization

		// sometimes, data symbols don't have a size. In that case, we must copy all data
		printf("Copy data\n");
		copy_data(src, oo);
	}
}

static void write_output_objects(linked_list *oo_list)
{
	backend_object *oo;

	// pop each object from the list, write it to a file
	for (; oo = (backend_object*)ll_pop(oo_list); oo != NULL)
	{
		if (close_output_object(oo) != 0)
			printf("Error writing %s\n", oo->name);
	}
}

static backend_object* get_output_object(linked_list *oo_list, const char* sym_name, backend_type output_target)
{
	backend_object *oo;
   char output_filename[MAX_FILENAME_LENGTH+1];

	// make the output name
	memset(output_filename, 0, MAX_FILENAME_LENGTH+1);
	strncpy(output_filename, sym_name, MAX_FILENAME_LENGTH-2); // leave 2 chars for ".o"
	char *lastdot = strrchr(output_filename, '.');
	if (lastdot)
		*lastdot = 0;
	strcat(output_filename, ".o");

	// first, check to see if there is already a backend object with this name
	for (const list_node* iter = ll_iter_start(oo_list); iter != NULL; iter=iter->next)
	{
		oo = (backend_object*)iter->val;
		if (strcmp(oo->name, output_filename) == 0)
			break;

		oo = NULL;
	}

	if (!oo)
	{
		// set up new output file
		oo = backend_create();

		if (oo)
		{
			if (config.verbose)
				fprintf(stderr, "=== Opening file %s\n", output_filename);
			printf("=== Opening file %s\n", output_filename);
			backend_set_type(oo, output_target);
			backend_set_filename(oo, output_filename);
			ll_push(oo_list, oo);
		}
	}

	return oo;
}

static int
unlink_file(const char* input_filename, backend_type output_target)
{
	backend_object* obj; 
   backend_object* oo = NULL;

	// print ignore list
	printf("Ignore list:\n");
   for (const list_node* iter=ll_iter_start(config.ignore_list); iter != NULL; iter=iter->next)
   {
		char *sym = (char*)iter->val;
		printf(" > %s\n", sym);
	}

	// read the input file into a generic backend structure
   if (config.verbose)
      fprintf(stderr, "Reading input file %s\n", input_filename);
   obj = backend_read(input_filename);
	if (!obj)
		return -ERR_BAD_FORMAT;

	// check for symbols, and rebuild if necessary
	if (backend_symbol_count(obj) == 0 && backend_import_symbol_count(obj) == 0 && config.reconstruct_symbols == 0)
		return -ERR_NO_SYMS;
	else if (config.reconstruct_symbols)
	{
      if (config.verbose)
         fprintf(stderr, "Reconstructing symbols with built-in function detector\n");

		reconstruct_symbols(obj, 1);
		//nucleus_reconstruct_symbols(obj);
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
	linked_list *oo_list = ll_init();
   backend_symbol* sym = backend_get_first_symbol(obj);
	if (config.symbol_per_file)
   {
		while (sym)
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

				oo = get_output_object(oo_list, sym->name, output_target);
				if (!oo)
					printf("Error getting output object\n");

				if (write_symbol(oo, obj, sym, output_target) < 0)
					printf("Error adding function symbol for %s\n", sym->name);

				copy_relocations(obj, oo);
				//printf("Fixup function data\n");
				//fixup_function_data(oo); //this seems like a poorly written optimization

				// sometimes, data symbols don't have a size. In that case, we must copy all data
				//printf("Copy data\n");
				//copy_data(obj, oo);

				// close output file
				close_output_object(oo);
				break;
			}
			sym = backend_get_next_symbol(obj);
		}
	}
	else
	{
		DEBUG_PRINT("Outputting to original .o files\n");
		while (sym)
		{
			DEBUG_PRINT("Processing %s type=%s size=%lu\n", sym->name, backend_symbol_type_to_str(sym->type), sym->size);
			if (ignore_symbol(sym) || !sym->src)
			{
				DEBUG_PRINT("Ignoring %s\n", sym->name);
				goto skip_ext;
			}

			if (sym->type == SYMBOL_TYPE_FUNCTION || sym->type == SYMBOL_TYPE_OBJECT)
			{
				DEBUG_PRINT("Getting output object for symbol %s\n", sym->name);
				oo = get_output_object(oo_list, sym->src, output_target);

				if (write_symbol(oo, obj, sym, output_target) < 0)
					printf("Error adding function symbol for %s\n", sym->name);
			}
skip_ext:
			sym = backend_get_next_symbol(obj);
		}

		finalize_objects(oo_list, obj);

		// write out all objects to files
		write_output_objects(oo_list);
	}
	ll_destroy(oo_list);
	oo_list = NULL;

	return 0;
}

int
main (int argc, char *argv[])
{
   int status = 0;
   char *input_filename = NULL;
   char *output_target = NULL;

	config.ignore_list = ll_init(); // list of symbols to ignore

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
      c = getopt_long (argc, argv, "I:O:RSv", options, 0);
      if (c == -1)
      break;

      switch (c)
      {
		case 'I':
			ll_push(config.ignore_list, strdup(optarg));
			break;

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

	// clean up ignore list
   for (const list_node* iter=ll_iter_start(config.ignore_list); iter != NULL; iter=iter->next)
		free((char*)iter->val);
	ll_destroy(config.ignore_list);

   return status;
}
