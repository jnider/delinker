/* Generic backend header file

Define the interface for target-specific backend implementations, as well as the
public functions for talking to backends */

/* To add a new backend, read instructions in backend.c */

#include "ll.h"

#define SECTION_FLAG_INIT_DATA	(1<<SECTION_FLAG_SHIFT_INIT_DATA)
#define SECTION_FLAG_UNINIT_DATA	(1<<SECTION_FLAG_SHIFT_UNINIT_DATA)
#define SECTION_FLAG_COMMENTS		(1<<SECTION_FLAG_SHIFT_COMMENTS)
#define SECTION_FLAG_DISCARDABLE	(1<<SECTION_FLAG_SHIFT_DISCARDABLE)
#define SECTION_FLAG_EXECUTE		(1<<SECTION_FLAG_SHIFT_EXECUTE)
#define SECTION_FLAG_READ			(1<<SECTION_FLAG_SHIFT_READ)
#define SECTION_FLAG_WRITE			(1<<SECTION_FLAG_SHIFT_WRITE)

#define SYMBOL_FLAG_GLOBAL 	(1<<SYMBOL_FLAG_SHIFT_GLOBAL)
#define SYMBOL_FLAG_EXTERNAL 	(1<<SYMBOL_FLAG_SHIFT_EXTERNAL)

typedef enum backend_type
{
   OBJECT_TYPE_NONE,
   OBJECT_TYPE_PE32,
   OBJECT_TYPE_PE_ROM,
   OBJECT_TYPE_PE32PLUS,
   OBJECT_TYPE_ELF32,
   OBJECT_TYPE_ELF64
} backend_type;

typedef enum backend_arch
{
   OBJECT_ARCH_UNKNOWN,
   OBJECT_ARCH_ARM,
   OBJECT_ARCH_ARM64,
   OBJECT_ARCH_X86,
   OBJECT_ARCH_MIPS,
   OBJECT_ARCH_PPC,
} backend_arch;

typedef enum backend_symbol_type
{
   SYMBOL_TYPE_NONE,
   SYMBOL_TYPE_FILE,
   SYMBOL_TYPE_SECTION,
   SYMBOL_TYPE_FUNCTION,
	SYMBOL_TYPE_OBJECT,
} backend_symbol_type;

typedef enum backend_section_flag
{
	SECTION_FLAG_SHIFT_INIT_DATA,
	SECTION_FLAG_SHIFT_UNINIT_DATA,
	SECTION_FLAG_SHIFT_COMMENTS,
	SECTION_FLAG_SHIFT_DISCARDABLE,
	SECTION_FLAG_SHIFT_EXECUTE,
	SECTION_FLAG_SHIFT_READ,
	SECTION_FLAG_SHIFT_WRITE
} backend_section_flag;

/* Generic section types - these are not finalized by any means */
typedef enum backend_section_type
{
	SECTION_TYPE_NULL,	// Null sections are common in ELF files
	SECTION_TYPE_PROG,	// Contains executable code, data or tables required during execution
	SECTION_TYPE_SYMTAB,	// Symbol table
	SECTION_TYPE_STRTAB,	// String table
	SECTION_TYPE_RELA,	// Relocation table
	SECTION_TYPE_HASH,
	SECTION_TYPE_DYNAMIC,
	SECTION_TYPE_NOTE,
	SECTION_TYPE_NOBITS,
	SECTION_TYPE_REL,
	SECTION_TYPE_SHLIB,
	SECTION_TYPE_DYNSYM,
} backend_section_type;

typedef enum backend_symbol_flag
{
	SYMBOL_FLAG_SHIFT_GLOBAL,
	SYMBOL_FLAG_SHIFT_EXTERNAL,
} backend_symbol_flag;

typedef enum backend_reloc_type
{
	RELOC_TYPE_NONE,
	RELOC_TYPE_OFFSET,			// straight substitution for the symbol value
	RELOC_TYPE_PC_RELATIVE,		// a jump/branch address relative to the PC; requires an offset (addend) usually of -4, but architecture dependent
	RELOC_TYPE_PLT,				// for linking with a dynamic library function
} backend_reloc_type;

typedef struct backend_section
{
//   unsigned int index;
   char* name;
   unsigned int size;
   unsigned long address;	// base address for loading this section
   unsigned int flags;		// see SECTION_FLAG_
	unsigned int type;		// see SECTION_TYPE_
   unsigned char* data;
   unsigned int alignment; // 2**x
	unsigned int entry_size;
////// private data ///////
	int _name;					// used to hold the index into the string table when writing
} backend_section;

typedef struct backend_symbol
{
   char* name;
   unsigned long val;
   backend_symbol_type type; // see SYMBOL_TYPE_
   unsigned int flags; // see SYMBOL_FLAGS_
	unsigned long size;
	char *src; // source filename (if known)
   backend_section* section;
} backend_symbol;

typedef struct backend_reloc
{
	unsigned long offset;
	long addend;
	backend_reloc_type type;
	backend_symbol* symbol;
} backend_reloc;

// an import is a module containing a name, and a list of function symbols that the code
// depends on. That means these functions must be present (i.e. dynamically linked) at a later time
// if this code is to run.
typedef struct backend_import
{
	char* name;
   linked_list* symbols;
} backend_import;

typedef struct backend_object
{
	char *name;			// name of file for storing the object
	backend_arch arch; // the target architecture (after all, the code is compiled for a particular ISA)
   backend_type type; // the file format that should be used when writing the file - this may go away, and become a parameter to backend_write() instead
	unsigned long entry;	// the entry point for linked files

   linked_list* section_table;
   linked_list* symbol_table;
   linked_list* relocation_table;
   linked_list* import_table;

   const list_node* iter_symbol;
   const list_node* iter_symbol_t;
   const list_node* iter_section;
   const list_node* iter_reloc;
   const list_node* iter_import_table;
   const list_node* iter_import_symbol;
} backend_object;

// the interface that must be implemented by a particular backend implementation - mainly for serializing to disk (and deserializing from disk)
typedef struct backend_ops
{
	const char* (*name)(void);
   backend_type (*format)(void);
   backend_object* (*read)(const char* filename);
   int (*write)(backend_object* obj, const char* filename);
} backend_ops;

// backend-specific sorting comparator
typedef int(*backend_cmpfunc)(void* item_a, void* item_b);

// global operations
int backend_init(void); /* initialize the library for use - don't call any functions before this one */
void backend_register(backend_ops* be); /* register specific backend implementation so it is known to the library */
backend_type backend_lookup_target(const char* name); /* given a string, find a backend that understands the type and convert to a known value to later be used with backend_set_type() */
const char* backend_get_first_target(void);
const char* backend_get_next_target(void);
const char* backend_symbol_type_to_str(backend_symbol_type t); /* output the name of the type as a string */

// general
backend_object* backend_create(void); /* the constructor - make an empty backend object */
void backend_destructor(backend_object* obj); /* the destructor - clean up and delete everything */
backend_object* backend_read(const char* filename);
int backend_write(backend_object* obj);
void backend_set_filename(backend_object* obj, const char* name);
void backend_set_type(backend_object* obj, backend_type t);
backend_type backend_get_type(backend_object* obj);
void backend_set_arch(backend_object* obj, backend_arch a);
backend_arch backend_get_arch(backend_object* obj);
void backend_set_entry_point(backend_object* obj, unsigned long addr);
unsigned long backend_get_entry_point(backend_object* obj);

// symbols
unsigned int backend_symbol_count(backend_object* obj);
backend_symbol* backend_add_symbol(backend_object* obj, const char* name, unsigned long val, backend_symbol_type type, unsigned long size, unsigned int flags, backend_section* sec);
backend_symbol* backend_get_first_symbol(backend_object* obj);
backend_symbol* backend_get_next_symbol(backend_object* obj);
backend_symbol* backend_get_symbol_by_type_first(backend_object* obj, backend_symbol_type type);
backend_symbol* backend_get_symbol_by_type_next(backend_object* obj, backend_symbol_type type);
backend_symbol* backend_find_symbol_by_val(backend_object* obj, unsigned long val);
backend_symbol* backend_find_symbol_by_name(backend_object* obj, const char* name);
backend_symbol* backend_find_symbol_by_index(backend_object* obj, unsigned int index);
backend_symbol* backend_find_symbol_by_val_type(backend_object* obj, unsigned long val, backend_symbol_type type);
backend_symbol* backend_find_nearest_symbol(backend_object* obj, unsigned long val);
unsigned int backend_get_symbol_index(backend_object* obj, backend_symbol* s); // if the symbol table were to be serialized, what would be the index of this symbol in the table?
backend_symbol* backend_split_symbol(backend_object* obj, backend_symbol *sym, const char* name, unsigned long val, backend_symbol_type type, unsigned int flags);
int backend_remove_symbol_by_name(backend_object* obj, const char* name);
int backend_sort_symbols(backend_object* obj, backend_cmpfunc cmp);
void backend_set_source_file(backend_symbol *s, const char *source_filename);

// sections
unsigned int backend_section_count(backend_object* obj);
backend_section* backend_add_section(backend_object* obj, const char* name, unsigned long size, unsigned long address,
   unsigned char* data, unsigned int entry_size, unsigned int alignment, unsigned long flags);
void backend_section_set_type(backend_section *s, backend_section_type t);
backend_section* backend_find_section_by_val(backend_object* obj, unsigned long val);
backend_section* backend_get_section_by_index(backend_object* obj, unsigned int index);
backend_section* backend_get_section_by_name(backend_object* obj, const char* name);
backend_section* backend_get_section_by_type(backend_object* obj, unsigned int t);
backend_section* backend_get_section_by_address(backend_object* obj, unsigned long address);
int backend_get_section_index_by_name(backend_object* obj, const char* name);
backend_section* backend_get_first_section(backend_object* obj);
backend_section* backend_get_next_section(backend_object* obj);
backend_section* backend_get_first_section_by_type(backend_object* obj, backend_section_type t);
backend_section* backend_get_next_section_by_type(backend_object* obj, backend_section_type t);
backend_symbol* backend_get_section_symbol(backend_object* obj, backend_section* sec);

// relocations
unsigned int backend_relocation_count(backend_object* obj);
int backend_add_relocation(backend_object* obj, unsigned long offset, backend_reloc_type t, long addend, backend_symbol* bs);
backend_reloc* backend_find_reloc_by_offset(backend_object* obj, unsigned long val);
backend_reloc* backend_get_first_reloc(backend_object* obj);
backend_reloc* backend_get_next_reloc(backend_object* obj);
const char* backend_lookup_reloc_type(backend_reloc_type t);

// imports
backend_import* backend_add_import_module(backend_object* obj, const char* name);
backend_import* backend_find_import_module_by_name(backend_object* obj, const char* name);
backend_symbol* backend_add_import_function(backend_import* mod, const char* name, unsigned long val);
backend_symbol* backend_find_import_by_address(backend_object* obj, unsigned long addr);
backend_symbol* backend_get_first_import(backend_object* obj);
backend_symbol* backend_get_next_import(backend_object* obj);
unsigned int backend_import_symbol_count(backend_object* obj);
