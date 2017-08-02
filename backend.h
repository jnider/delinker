/* Generic backend header file

Define the interface for target-specific backend implementations, as well as the
public functions for talking to backends */

#include "ll.h"

typedef enum backend_type
{
   OBJECT_TYPE_NONE,
   OBJECT_TYPE_PE32,
   OBJECT_TYPE_PE_ROM,
   OBJECT_TYPE_PE32PLUS,
   OBJECT_TYPE_ELF32
} backend_type;

typedef enum backend_symbol_type
{
   SYMBOL_TYPE_NONE,
   SYMBOL_TYPE_FILE
} backend_symbol_type;

typedef struct backend_section
{
   char* name;
   unsigned int size;
   unsigned int address;
   unsigned int flags;
   char* data;
} backend_section;

typedef struct backend_symbol
{
   char* name;
   unsigned int val;
   backend_symbol_type type;
   unsigned int flags;
   backend_section* section;
} backend_symbol;

typedef struct backend_object
{
   backend_type type;
   linked_list* section_table;
   linked_list* symbol_table;
   const list_node* iter_symbol;
} backend_object;

typedef struct backend_ops
{
   backend_type (*format)(void);
   backend_object* (*read)(const char* filename);
   int (*write)(backend_object* obj, const char* filename);
} backend_ops;

/* initialize the library for use - don't call any functions before this one */
int backend_init(void);

void backend_register();

backend_object* backend_create(void);
backend_object* backend_read(const char* filename);
int backend_write(backend_object* obj, const char* filename);
void backend_set_type(backend_object* obj, backend_type t);
unsigned int backend_symbol_count(backend_object* obj);
int backend_add_symbol(backend_object* obj, const char* name, unsigned int val, backend_symbol_type type, unsigned int flags, backend_section* sec);
backend_symbol* backend_get_first_symbol(backend_object* obj);
backend_symbol* backend_get_next_symbol(backend_object* obj);

unsigned int backend_section_count(backend_object* obj);
int backend_add_section(backend_object* obj, char* name, unsigned int size, unsigned int address, char* data, unsigned int flags);
backend_section* backend_get_section(backend_object* obj, unsigned int index);
backend_section* backend_get_section_by_name(backend_object* obj, const char* name);
void backend_destructor(backend_object* obj);
