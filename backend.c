#include <stdio.h>
#include <string.h>
#include "backend.h"
#include "ll.h"

#define DECLARE_BACKEND_INIT_FUNC(_x) extern int _x##_init()
#define BACKEND_INIT_FUNC(_x) _x##_init

DECLARE_BACKEND_INIT_FUNC(pe);
DECLARE_BACKEND_INIT_FUNC(elf);


typedef int (*backend_init_func)(void);
static backend_init_func backend_table[] = 
{
	BACKEND_INIT_FUNC(pe),
	BACKEND_INIT_FUNC(elf),
};

#define BACKEND_INIT(_x) backend_table[_x]
#define BACKEND_COUNT sizeof(backend_table)/sizeof(void*)

static int num_backends;
static backend_ops* backend[BACKEND_COUNT] = {0};

int backend_init(void)
{
	int i;
	for (i=0; i < BACKEND_COUNT; i++)
	{
		if (BACKEND_INIT(i))
			BACKEND_INIT(i)();
	}

	return 0;
}

void backend_register(backend_ops* be)
{
   if (num_backends >= BACKEND_COUNT)
   {
      printf("Can't accept any more backends - sorry, we're full! (MAX_BACKENDS=%lu)\n", BACKEND_COUNT);
      return;
   }

   if (!be->format)
   {
      printf("You must implement the format() function\n");
      return;
   }

   backend[num_backends++] = be;
   printf("num backends %i\n", num_backends);
}

backend_object* backend_create(void)
{
   backend_object* obj = malloc(sizeof(backend_object));
   if (obj)
   {
      obj->type = OBJECT_TYPE_NONE;
      obj->section_table = NULL;
      obj->symbol_table = NULL;
   }
   return obj;
}

backend_object* backend_read(const char* filename)
{
   printf("backend_read\n");
   // run through all backends until we find one that recognizes the format and returns an object
   for (int i=0; i < num_backends; i++)
   {
      backend_object* obj = backend[i]->read(filename);
      if (obj)
         return obj;
   }
   return 0;
}

int backend_write(backend_object* obj, const char* filename)
{
   // run through all backends until we find one that matches the output format
   for (int i=0; i < num_backends; i++)
   {
      if (backend[i]->format() == obj->type)
      {
         if (!backend[i]->write)
            return -2;

         backend[i]->write(obj, filename);
         return 0;
      }
   }
   return -1;
}

void backend_set_type(backend_object* obj, backend_type t)
{
   obj->type = t;
}

void backend_set_address(backend_object* obj, unsigned int addr)
{
	obj->address = addr;
}

unsigned int backend_symbol_count(backend_object* obj)
{
   if (obj->symbol_table)
      return ll_size(obj->symbol_table);
   else
      return 0;
}

int backend_add_symbol(backend_object* obj, const char* name, unsigned int val, backend_symbol_type type, unsigned int flags, backend_section* sec)
{
   if (!obj->symbol_table)
      obj->symbol_table = ll_init();

   backend_symbol* s = malloc(sizeof(backend_symbol));
   s->name = strdup(name);
   s->val = val;
   s->type = type;
   s->flags = flags;
   s->section = sec;
   //printf("Adding %s\n", s->name);
   ll_add(obj->symbol_table, s);
   //printf("There are %i symbols\n", backend_symbol_count(obj));
   return 0;
}

backend_symbol* backend_get_first_symbol(backend_object* obj)
{
   if (!obj->symbol_table)
      return NULL;
   obj->iter_symbol = ll_iter_start(obj->symbol_table);
   return obj->iter_symbol->val;
}

backend_symbol* backend_get_next_symbol(backend_object* obj)
{
   obj->iter_symbol = obj->iter_symbol->next; 
   if (obj->iter_symbol)
      return obj->iter_symbol->val;
   return NULL;
}
///////////////////////////////////////////
unsigned int backend_section_count(backend_object* obj)
{
   if (!obj->section_table)
   {
      printf("No generic section table\n");
      return 0;
   }
   return ll_size(obj->section_table);
}

backend_section* backend_add_section(backend_object* obj, unsigned int index, char* name, unsigned int size, unsigned int address, char* data, unsigned int alignment, unsigned int flags)
{
   if (!obj->section_table)
      obj->section_table = ll_init();

   backend_section* s = malloc(sizeof(backend_section));
	if (!s)
		return NULL;

   s->name = name;
   s->size = size;
   s->address = address;
   s->flags = flags;
   s->data = data;
   //printf("Adding section %s size:%i address:0x%x flags:0x%x\n", s->name, s->size, s->address, s->flags);
   ll_add(obj->section_table, s);
   //printf("There are %i sections\n", backend_section_count(obj));
   return s;
}

backend_section* backend_get_section_by_index(backend_object* obj, unsigned int index)
{
   for (const list_node* iter=ll_iter_start(obj->section_table); iter != NULL; iter=iter->next)
   {
      backend_section* sec = iter->val;
      if (sec->index == index)
         return sec;
   }
   return NULL;
}

backend_section* backend_get_section_by_name(backend_object* obj, const char* name)
{
	if (!obj || !name || !obj->section_table)
		return NULL;

   for (const list_node* iter=ll_iter_start(obj->section_table); iter != NULL; iter=iter->next)
   {
      backend_section* sec = iter->val;
      //printf(".. %s\n", sec->name);
      if (!strcmp(name, sec->name))
         return sec;
   }
   return NULL;
}

backend_section* backend_get_first_section(backend_object* obj)
{
   if (!obj->section_table)
      return NULL;
   obj->iter_section = ll_iter_start(obj->section_table);
   return obj->iter_section->val;
}

backend_section* backend_get_next_section(backend_object* obj)
{
   obj->iter_section = obj->iter_section->next; 
   if (obj->iter_section)
      return obj->iter_section->val;
   return NULL;
}

void backend_destructor(backend_object* obj)
{
   // destroy the symbol table
   if (obj->symbol_table)
   {
      backend_symbol* s = ll_pop(obj->symbol_table);
      while (s)
      {
         printf("Popped %s\n", s->name);
         //free(s->name);
         //free(s);
         s = ll_pop(obj->symbol_table);
      }
   }

   // and finally the object itself
   free(obj);
}
