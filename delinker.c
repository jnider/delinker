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
#include "reloc.h"

#ifdef DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT //
#endif

extern int nucleus_reconstruct_symbols(backend_object *obj);
extern void reloc_x86_16(backend_object* obj, backend_section* sec, csh cs_dis, cs_insn *cs_ins);
extern void reloc_x86_32(backend_object* obj, backend_section* sec, csh cs_dis, cs_insn *cs_ins);
extern void reloc_x86_64(backend_object* obj, backend_section* sec, csh cs_dis, cs_insn *cs_ins);

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
  {"entry-name", required_argument, 0, 'e'},
  {"ignore", required_argument, 0, 'I'},
  {"output-target", required_argument, 0, 'O'},
  {"reconstruct-symbols", required_argument, 0, 'R'},
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
   fprintf(stderr, "-e, --entry-name\tSet the name of the entry point function\n");
   fprintf(stderr, "-R, --reconstruct-symbols\tRebuild the symbol table by various techniques. Use -R ? to see the options\n");
   fprintf(stderr, "-S, --symbol-per-file\t\tCreate a separate .o file for each function\n");
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

static int extraneous_cmp(void* a, const void* b)
{
	backend_symbol* symbol_a = (backend_symbol*)a;
	backend_symbol* symbol_b = (backend_symbol*)b;
	return (!(symbol_a->val == symbol_b->val));
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

static int reconstruct_symbols_x86_16(csh cs_dis, cs_insn *cs_ins, backend_object *obj, backend_section *sec_text, const char *src_name)
{
	uint64_t pc_addr;
	const uint8_t *pc;
	size_t length;
	unsigned long prev_addr = 0;
	char name[24];
	int eof = 0;
	int padding = 1;

	DEBUG_PRINT("Reconstructing x86_16 symbols\n");
	pc = sec_text->data;
	length = sec_text->size;
	pc_addr = sec_text->address;
	while(cs_disasm_iter(cs_dis, &pc, &length, &pc_addr, cs_ins))
	{
		backend_symbol *s;
		// did we hit the official end of the function?
		if (cs_ins->id == X86_INS_RET || cs_ins->id == X86_INS_IRET ||
			cs_ins->id == X86_INS_RETF)
		{
			eof = 1;
			//printf("end: 0x%lx: %s\n", cs_ins->address, cs_ins->mnemonic);

			// ignore any extraneous bytes after the 'ret' instruction
			if (!padding)
			{
				sprintf(name, "fn%06lX", prev_addr);
				s = backend_add_symbol(obj, name, prev_addr, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr + cs_ins->size, SYMBOL_FLAG_GLOBAL, sec_text);
				backend_set_source_file(s, "source.c");
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
					s = backend_add_symbol(obj, name, prev_addr, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr, SYMBOL_FLAG_GLOBAL, sec_text);
					backend_set_source_file(s, "source.c");
				}

				prev_addr = cs_ins->address;
			}
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

	// now add a symbol for each section - this is not the final order (that will be set when the object is written)
	// but why not keep them in some kind of order?
	backend_section* curr_sec = backend_get_first_section(obj);
	while (curr_sec)
	{
		backend_add_symbol(obj, curr_sec->name, 0, SYMBOL_TYPE_SECTION, 0, 0, curr_sec);
		curr_sec = backend_get_next_section(obj);
	}

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
	switch(t)
	{
	case OBJECT_TYPE_MZ:
		cs_mode = CS_MODE_16;
		break;

	case OBJECT_TYPE_ELF32:
	case OBJECT_TYPE_PE32:
		cs_mode = CS_MODE_32;
		break;

	case OBJECT_TYPE_ELF64:
		cs_mode = CS_MODE_64;
		break;

	default:
		return -ERR_BAD_FORMAT;
	}
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
	else if (t == OBJECT_TYPE_MZ && arch == CS_ARCH_X86)
		reconstruct_symbols_x86_16(cs_dis, cs_ins, obj, sec_text, fake_src_name);
	else
	while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins))
	{
		backend_symbol *s;
		// did we hit the official end of the function?
		if (cs_ins->id == X86_INS_IRET || cs_ins->id == X86_INS_JMP)
		{
			eof = 1;
			//printf("end: 0x%lx: %s\n", cs_ins->address, cs_ins->mnemonic);

			// ignore any extraneous bytes after the 'ret' instruction
			if (!padding)
			{
				sprintf(name, "fn%06lX", prev_addr);
				s = backend_add_symbol(obj, name, prev_addr, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr + cs_ins->size, SYMBOL_FLAG_GLOBAL, sec_text);
				backend_set_source_file(s, "source.c");
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
					s = backend_add_symbol(obj, name, prev_addr, SYMBOL_TYPE_FUNCTION, cs_ins->address - prev_addr, SYMBOL_FLAG_GLOBAL, sec_text);
					backend_set_source_file(s, "source.c");
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
	uint64_t entry = backend_get_entry_point(obj);
	backend_symbol *bs = backend_find_symbol_by_val_type(obj, entry, SYMBOL_TYPE_FUNCTION);
	if (bs)
	{
		if (bs->val == entry)
		{
			DEBUG_PRINT("found entry point %s @ 0x%lx - renaming to '%s'\n", bs->name, bs->val, config.entry_name);
			free(bs->name);
			bs->name = strdup(config.entry_name);
		}
		else
		{
			printf("Entry point is in the middle of a symbol - splitting\n");
			backend_split_symbol(obj, bs, config.entry_name, entry, SYMBOL_TYPE_FUNCTION, SYMBOL_FLAG_GLOBAL);
		}
	}
	else
	{
		printf("No symbol for entry point @ 0x%lx - the recovery is not very accurate\n", backend_get_entry_point(obj));
      //backend_add_symbol(obj, config.entry_name, entry, SYMBOL_TYPE_FUNCTION, size, flags, section);
	}

	printf("%u symbols after reconstruction\n", backend_symbol_count(obj) - start_count);
	cs_free(cs_ins, 1);
	cs_close(&cs_dis);

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

int create_reloc(backend_object *obj, backend_reloc_type rt, unsigned int val, int offset, unsigned int hint)
{
	backend_symbol *bs=NULL;
	backend_section* sec;
	static int data_symbols;
	int addend = 0;

	DEBUG_PRINT("[0x%x]: looking up symbol[%u] @ 0x%x - ", offset, hint, val);

	// First, find the section that this symbol belongs in
	sec = backend_find_section_by_val(obj, val);
	if (!sec)
	{
		printf("  Address 0x%x doesn't have a containing section\n", val);
		return -2;
	}

	// Warning, not error. MZ files are basically linked at 0x0000
	if (sec->address == 0)
	{
		printf("Warning:  section %s has a zero address\n", sec->name);
		//return -3;
	}

	if (!(sec->flags & SECTION_FLAG_INIT_DATA | SECTION_FLAG_UNINIT_DATA | SECTION_FLAG_EXECUTE))
	{
		printf("  section %s is not a program section\n", sec->name);
		return -4;
	}

	// Check to see if this is a known symbol
	// If the hint says this should be a function, look for a function explicitly. This avoids the
	// situation that there are multiple symbols at the same address, which can happen in backends
	// like MZ, where the data section completely overlaps the data section.
	if (hint == RELOC_HINT_CALL || hint == RELOC_HINT_JUMP)
		bs = backend_find_symbol_by_val_type(obj, val, SYMBOL_TYPE_FUNCTION);
	if (!bs)
		bs = backend_find_symbol_by_val(obj, val);
	if (bs)
	{
		if (bs->type != SYMBOL_TYPE_FUNCTION && bs->type != SYMBOL_TYPE_OBJECT)
		{
			printf("  symbol %s is not a function or data object\n", bs->name);
			return -5;
		}

		// This is some complicated logic. In the case of mixed data/code sections (which happens
		// with old formats like MZ) if a relocation comes in and lands in the middle of a function,
		// it is possible that the function reconstruction was imprecise. To detect that scenario,
		// we check to see if the address is precisely equal to the symbol that we found. If not,
		// we rely on the hint to know if this is a function or not. If it is a function, we split
		// the symbol. Otherwise we check to see if this section is also a data section.
		// If it is, then assume this is a data symbol.
		if (bs->type == SYMBOL_TYPE_FUNCTION)
		{
			//DEBUG_PRINT("  Found function symbol %s\n", bs->name);
			if (bs->val != val)
			{
				DEBUG_PRINT("  Function symbol %s not precise\n", bs->name);

				if (hint == RELOC_HINT_CALL)
				{
					char name[24];
					// we _know_ this is a function because it came from a CALL instruction
					// that implies there is probably a missing symbol, due to errors in the
					// symbol reconstruction algorithm. So let's just add the symbol and hope
					// it's correct.
					//DEBUG_PRINT("  Function symbol split at 0x%x\n", val);
					sprintf(name, "fn%06X", val);
					bs = backend_split_symbol(obj, bs, name, val, SYMBOL_TYPE_FUNCTION, SYMBOL_FLAG_GLOBAL);
					if (!bs)
						printf("   Error splitting symbol\n");
					addend = -4;
				}
				else if (hint == RELOC_HINT_JUMP)
				{
					DEBUG_PRINT("  Jump to 0x%x\n", val);
					addend = (val - bs->val) - 4;
				}
				else if (sec->flags & SECTION_FLAG_INIT_DATA | SECTION_FLAG_UNINIT_DATA)
				{
					DEBUG_PRINT("Relocation to data section - assuming data symbol\n");
					bs = NULL;
				}
			}
			else
			{
				// add a relocation
				addend = -4;
				//DEBUG_PRINT("   Creating relocation to function %s +%i @ 0x%x\n", bs->name, addend, offset);
			}
		}
	}

	if (!bs)
	{
		DEBUG_PRINT("  No known symbol for 0x%x but it is in section %s %u\n", val, sec->name, sec->type);

		// symbol must be in a program section (GOT, PLT, data, code or BSS)
		if (sec->type == SECTION_TYPE_NOBITS)
		{
			if (strcmp(sec->name, ".bss") != 0)
				printf("Warning: NOBITS section has name other than .bss - this is unusual\n");
		}
		else if (sec->type != SECTION_TYPE_PROG)
		{
			printf("Symbol is not in a program section - no good\n");
			return -6;
		}

		if (!bs && sec->flags & SECTION_FLAG_EXECUTE)
		{
			// Maybe it has an import symbol
			//DEBUG_PRINT("Checking for import symbol @ %x\n", val);
			bs = backend_find_import_by_address(obj, val);
			if (bs)
			{
				printf("  Found import symbol %s (flags=%u)\n", bs->name, bs->flags);
				bs = backend_find_symbol_by_name(obj, bs->name);
				if (!bs)
				{
					return -11;
				}

				printf("   Creating (PLT) relocation to %s @ 0x%x\n", bs->name, offset);
				rt = RELOC_TYPE_PLT;
				addend = -4;
			}
			else if (strcmp(sec->name, ".plt.got") == 0)
			{
				printf("Not sure what to do with .plt.got symbols. They are dynamic but don't have an import??\n");
				return -7;
			}
/*
			else
			{
				printf("Can't find import symbol!\n");
				return -8;
			}
*/
		}

		if (!bs && (sec->flags & SECTION_FLAG_INIT_DATA) || (sec->flags & SECTION_FLAG_UNINIT_DATA))
		{
			// get the section symbol related to this section
			bs = backend_get_section_symbol(obj, sec);
			if (bs)
			{
				// add a relocation (for data only)
				if (rt == RELOC_TYPE_PC_RELATIVE)
				{
					addend = val - sec->address;
					printf("  Creating PC_REL to %s +0x%x\n", bs->name, addend);
				}
				else if (rt == RELOC_TYPE_OFFSET)
				{
					addend = val - sec->address;
					printf("  Creating REL_OFFSET to %s+%i @offset 0x%x\n", bs->name, addend, offset);
				}
				else
				{
					printf("Unknown relocation type: %i\n", rt);
					return -1;
				}
			}
			else
			{
				printf("Missing section symbol for %s\n", sec->name);
				return -1;
			}
		}
		else
		{
			// This might be a debug instruction, or just a 'mov' instruction that
			// shouldn't have a relocation at all.
			printf("Ignoring instruction - no reloc\n");
			return -1;
		}
	}

	return backend_add_relocation(obj, offset, rt, addend, bs);
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
	switch(t)
	{
	case OBJECT_TYPE_MZ:
		cs_mode = CS_MODE_16;
		break;

	case OBJECT_TYPE_ELF32:
	case OBJECT_TYPE_PE32:
		cs_mode = CS_MODE_32;
		break;

	case OBJECT_TYPE_ELF64:
		cs_mode = CS_MODE_64;
		break;

	default:
		return -ERR_BAD_FORMAT;
	}

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
		if (cs_arch == CS_ARCH_X86 && cs_mode == CS_MODE_16)
			rfn = reloc_x86_16;
		else if (cs_arch == CS_ARCH_X86 && cs_mode == CS_MODE_32)
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
			printf("Copying reloc @offset=%lx to symbol %s\n", r->offset, target->name);
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

				//printf("Adding relocation to symbol %s (offset=0x%x type=%i)\n", dest_target->name, offset, dest_target->type);
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

	DEBUG_PRINT("Output file has %u relocations\n", backend_relocation_count(dest));
/*
#ifdef DEBUG
	backend_reloc* tr = backend_get_first_reloc(dest);
	while (tr)
	{
		printf("** Symbol %s (val 0x%lx) Offset: 0x%lx\n", tr->symbol->name, tr->symbol->val, tr->offset);
		tr = backend_get_next_reloc(dest);
	}
#endif // DEBUG
*/

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
	//DEBUG_PRINT("Adding symbol %s @ 0x%lx (type=%i size=%lu) to %s\n", sym->name, sec_out->address+offset, sym->type, sym->size, oo->name);
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
	backend_symbol *sym;

	// print ignore list
	if (config.ignore_list->count)
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
		if (config.reconstructor == RECONSTRUCTOR_NUCLEUS)
		{
			if (config.verbose)
				fprintf(stderr, "Reconstructing symbols with 'nucleus' function detector\n");
			nucleus_reconstruct_symbols(obj);
		}
		else
		{
      	if (config.verbose)
				fprintf(stderr, "Reconstructing symbols with internal function detector\n");
			reconstruct_symbols(obj, 1);
		}
		if (backend_symbol_count(obj) == 0)
			return -ERR_NO_SYMS_AFTER_RECONSTRUCT;
	}

	if (config.verbose)
		printf("reconstruct complete\n");

	// convert any absolute addresses into symbols (loads of data, calls of functions, etc.)
	// make sure any relative jumps are still accurate
	int ret = build_relocations(obj);
	if (ret < 0)
	{
		printf("Can't build relocations: %s (%i)\n", error_code_str[-ret], ret);
      return ret;
	}
	if (config.verbose)
		printf("building relocs complete\n");

	if (config.verbose)
		printf("trimming extraneous symbols\n");
	// trim the extraneous symbols that were probably auto-generated
	// start with a full list of functions, and remove anything that has a reloc pointing to it
	linked_list *extraneous = ll_init();
   for (sym = backend_get_first_symbol(obj); sym; sym = backend_get_next_symbol(obj))
		ll_add(extraneous, sym);

	for (backend_reloc* r = backend_get_first_reloc(obj); r; r = backend_get_next_reloc(obj))
	{
		//printf("Reloc points to symbol %s\n", r->symbol->name);
		ll_remove(extraneous, r->symbol, extraneous_cmp);
		//printf("Remaining functions: %u\n", ll_size(extraneous));
	}

	if (config.verbose)
		printf("trimmed %u symbols\n", ll_size(extraneous));

	// anything that is left does not have a reloc pointing to it, and can be removed
	sym = (backend_symbol *)ll_pop(extraneous);
	while (sym)
	{
		//printf("Merging %s\n", sym->name);
		backend_merge_symbol(obj, sym);
		sym = (backend_symbol *)ll_pop(extraneous);
	}
	ll_destroy(extraneous);
	extraneous = NULL;

   // if the output target is not specified, use the input target
	if (output_target == OBJECT_TYPE_NONE)
	{
		output_target = backend_get_type(obj);
		printf("Warning: setting output type to match input: %i\n", output_target);
	}

	// Output symbols to .o files
	linked_list *oo_list = ll_init();
   sym = backend_get_first_symbol(obj);
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
			//DEBUG_PRINT("Processing %s type=%s size=%lu\n", sym->name, backend_symbol_type_to_str(sym->type), sym->size);
			if (ignore_symbol(sym) || !sym->src)
			{
				DEBUG_PRINT("Ignoring %s\n", sym->name);
				goto skip_ext;
			}

			if (sym->type == SYMBOL_TYPE_FUNCTION || sym->type == SYMBOL_TYPE_OBJECT)
			{
				//DEBUG_PRINT("Getting output object for symbol %s\n", sym->name);
				if (!sym->src)
				{
					printf("Skipping external function %s\n", sym->name);
					goto skip_ext;
				}

				printf("Writing symbol %s to %s\n", sym->name, sym->src);
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
      c = getopt_long (argc, argv, "e:I:O:R:Sv", options, 0);
      if (c == -1)
      break;

      switch (c)
      {
		case 'e':
			config.entry_name = strdup(optarg);
			break;

		case 'I':
			ll_push(config.ignore_list, strdup(optarg));
			break;

      case 'O':
         output_target = optarg;
         break;

      case 'R':
         config.reconstruct_symbols = 1;
			if (strcmp(optarg, "nucleus") == 0)
				config.reconstructor = RECONSTRUCTOR_NUCLEUS;
			else if (strcmp(optarg, "internal") == 0)
				config.reconstructor = RECONSTRUCTOR_INTERNAL;
			else
			{
				printf("Symbol Reconstruction Algorithms:\nUse one of the following strings after the -R to choose a specific algorithm\n");
				printf("nucleus: Nucleus algorithm\n");
				printf("internal: Internal algorithm\n");
				return -1;
			}
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
	if (!config.entry_name)
		config.entry_name = strdup(SYMBOL_NAME_MAIN);

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
