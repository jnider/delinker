/* Generic backend header file

Define the interface for target-specific backend implementations, as well as the
public functions for talking to backends */

/* To add a new backend, read instructions in backend.c */

#include "ll.h"

#define SECTION_FLAG_CODE 			(1<<SECTION_FLAG_SHIFT_CODE)
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
	SECTION_FLAG_SHIFT_CODE,
	SECTION_FLAG_SHIFT_INIT_DATA,
	SECTION_FLAG_SHIFT_UNINIT_DATA,
	SECTION_FLAG_SHIFT_COMMENTS,
	SECTION_FLAG_SHIFT_DISCARDABLE,
	SECTION_FLAG_SHIFT_EXECUTE,
	SECTION_FLAG_SHIFT_READ,
	SECTION_FLAG_SHIFT_WRITE
} backend_section_flag;

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
} backend_reloc_type;

typedef struct backend_section
{
//   unsigned int index;
   char* name;
   unsigned int size;
   unsigned long address;	// base address for loading this section
   unsigned int flags; // see SECTION_FLAG_
   char* data;
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
   backend_section* section;
} backend_symbol;

typedef struct backend_reloc
{
	unsigned long offset;
	backend_reloc_type type;
	backend_symbol* symbol;
} backend_reloc;

typedef struct backend_object
{
	// need to add another variable representing the target architecture (after all, the code is compiled for a particular ISA)
   backend_type type; // the file format that should be used when writing the file - this may go away, and become a parameter to backend_write() instead

   linked_list* section_table;
   linked_list* symbol_table;
   linked_list* relocation_table;

   const list_node* iter_symbol;
   const list_node* iter_section;
   const list_node* iter_reloc;

	unsigned long address;	// base address for loading
} backend_object;

// the interface that must be implemented by a particular backend implementation - mainly for serializing to disk (and deserializing from disk)
typedef struct backend_ops
{
	const char* (*name)(void);
   backend_type (*format)(void);
   backend_object* (*read)(const char* filename);
   int (*write)(backend_object* obj, const char* filename);
} backend_ops;

// global operations
int backend_init(void); /* initialize the library for use - don't call any functions before this one */
void backend_register(backend_ops* be); /* register specific backend implementation so it is known to the library */
backend_type backend_lookup_target(const char* name); /* given a string, find a backend that understands the type and convert to a known value to later be used with backend_set_type() */

// general
backend_object* backend_create(void); /* the constructor - make an empty backend object */
void backend_destructor(backend_object* obj); /* the destructor - clean up and delete everything */
backend_object* backend_read(const char* filename);
int backend_write(backend_object* obj, const char* filename);
void backend_set_type(backend_object* obj, backend_type t);
backend_type backend_get_type(backend_object* obj);
void backend_set_address(backend_object* obj, unsigned long addr); // set base address for loading the object
void backend_set_entry_point(backend_object* obj, unsigned long addr);

// symbols
unsigned int backend_symbol_count(backend_object* obj);
backend_symbol* backend_add_symbol(backend_object* obj, const char* name, unsigned long val, backend_symbol_type type, unsigned long size, unsigned int flags, backend_section* sec);
backend_symbol* backend_get_first_symbol(backend_object* obj);
backend_symbol* backend_get_next_symbol(backend_object* obj);
backend_symbol* backend_find_symbol_by_val(backend_object* obj, unsigned long val);
backend_symbol* backend_find_symbol_by_name(backend_object* obj, const char* name);
backend_symbol* backend_find_symbol_by_index(backend_object* obj, unsigned int index);
unsigned int backend_get_symbol_index(backend_object* obj, backend_symbol* s); // if the symbol table were to be serialized, what would be the index of this symbol in the table?
int backend_remove_symbol_by_name(backend_object* obj, const char* name);

// sections
unsigned int backend_section_count(backend_object* obj);
backend_section* backend_add_section(backend_object* obj, char* name, unsigned long size, unsigned long address, char* data, unsigned int entry_size, unsigned int alignment, unsigned long flags);
backend_section* backend_get_section_by_index(backend_object* obj, unsigned int index);
backend_section* backend_get_section_by_name(backend_object* obj, const char* name);
int backend_get_section_index_by_name(backend_object* obj, const char* name);
backend_section* backend_get_first_section(backend_object* obj);
backend_section* backend_get_next_section(backend_object* obj);

// relocations
unsigned int backend_relocation_count(backend_object* obj);
int backend_add_relocation(backend_object* obj, unsigned long offset, backend_reloc_type t, backend_symbol* bs);
backend_reloc* backend_find_reloc_by_offset(backend_object* obj, unsigned long val);
backend_reloc* backend_get_first_reloc(backend_object* obj);
backend_reloc* backend_get_next_reloc(backend_object* obj);
