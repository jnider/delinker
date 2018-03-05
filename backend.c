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

static int backend_iter;

int backend_init(void)
{
	// here we use the macro BACKEND_COUNT to know how many backends exist. This is different
	// from num_backends which is how many backends have been registered (initialized successfully).
	for (int i=0; i < BACKEND_COUNT; i++)
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
   //printf("num backends %i\n", num_backends);
}

backend_type backend_lookup_target(const char* name)
{
	if (!name)
   	return OBJECT_TYPE_NONE;

	// iterate through all known backends, comparing the string. When we find a match, convert the name to the correct type
   for (int i=0; i < num_backends; i++)
   {
		//printf("Looking up %i\n", i);
		//printf("Found backend %s\n", backend[i]->name());
      if (backend[i]->name && strcmp(backend[i]->name(), name) == 0)
			return backend[i]->format();
   }
   return OBJECT_TYPE_NONE;
}

const char* backend_get_first_target(void)
{
	backend_iter = 0;

	if (num_backends == 0)
		return NULL;

	return backend[backend_iter++]->name();
}

const char* backend_get_next_target(void)
{
	if (backend_iter < num_backends)
		return backend[backend_iter++]->name();

	return NULL;
}

backend_object* backend_create(void)
{
   backend_object* obj = calloc(1, sizeof(backend_object));
   return obj;
}

backend_object* backend_read(const char* filename)
{
   //printf("backend_read\n");
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
	//printf("backend_write looking for type %i\n", obj->type);
   // run through all backends until we find one that matches the output format
   for (int i=0; i < num_backends; i++)
   {
      if (backend[i]->format() == obj->type)
      {
         if (!backend[i]->write)
            return -2;

			//printf("Using backend %i\n", i);
         backend[i]->write(obj, filename);
         return 0;
      }
   }

   return -1;
}

void backend_set_type(backend_object* obj, backend_type t)
{
	//printf("setting backend type to %i\n", t);
   obj->type = t;
}

backend_type backend_get_type(backend_object* obj)
{
	return obj->type;
}

void backend_set_address(backend_object* obj, unsigned long addr)
{
	obj->address = addr;
}

unsigned int backend_symbol_count(backend_object* obj)
{
   if (obj && obj->symbol_table)
      return ll_size(obj->symbol_table);
   else
      return 0;
}

backend_symbol* backend_add_symbol(backend_object* obj, const char* name, unsigned long val, backend_symbol_type type, unsigned long size, unsigned int flags, backend_section* sec)
{
   if (!obj->symbol_table)
      obj->symbol_table = ll_init();

   backend_symbol* s = malloc(sizeof(backend_symbol));
   s->name = strdup(name);
   s->val = val;
   s->type = type;
	s->size = size;
   s->flags = flags;
   s->section = sec;
   //printf("Adding %s type=%i size=%lu val=0x%lx\n", s->name, s->type, s->size, s->val);
   ll_add(obj->symbol_table, s);
   //printf("There are %i symbols\n", backend_symbol_count(obj));
   return s;
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

backend_symbol* backend_find_symbol_by_val(backend_object* obj, unsigned long val)
{
	backend_symbol* bs;

   if (!obj->symbol_table)
      return NULL;

   for (const list_node* iter=ll_iter_start(obj->symbol_table); iter != NULL; iter=iter->next)
	{
		bs = iter->val;
		//printf("** %s 0x%lx\n", bs->name, bs->val);
		if (bs->val == val)
			return bs;
	}

	return NULL;
}

backend_symbol* backend_find_symbol_by_name(backend_object* obj, const char* name)
{
	backend_symbol* bs;

   if (!obj || !obj->symbol_table)
      return NULL;

   for (const list_node* iter=ll_iter_start(obj->symbol_table); iter != NULL; iter=iter->next)
	{
		bs = iter->val;
		if (strcmp(bs->name, name) == 0)
			return bs;
	}

	return NULL;
}

backend_symbol* backend_find_symbol_by_index(backend_object* obj, unsigned int index)
{
   if (!obj || !obj->symbol_table)
      return NULL;

   const list_node* iter=ll_iter_start(obj->symbol_table);
	for (unsigned int i=0; i < index; i++)
	{
		if (!iter)
			return NULL;
		iter=iter->next;
	}
	if (iter)
		return iter->val;

	return NULL;
}

unsigned int backend_get_symbol_index(backend_object* obj, backend_symbol* s)
{
	unsigned int count = 0;

   if (!obj || !obj->symbol_table || !s)
      return (unsigned int)-1;

	//printf("+ %s\n", s->name);
   for (const list_node* iter=ll_iter_start(obj->symbol_table); iter != NULL; iter=iter->next)
	{
		//printf("** %s\n", ((backend_symbol*)(iter->val))->name);
		if (iter->val == s)
			return count;
		count++;
	}

	return (unsigned int)-1;
}

static int cmp_by_name(void* a, const void* b)
{
	backend_symbol* s = a;
	const char* name = b;
	return strcmp(s->name, name);
}

int backend_remove_symbol_by_name(backend_object* obj, const char* name)
{
	backend_symbol* bs;

   if (!obj || !obj->symbol_table)
      return -1;

	bs = ll_remove(obj->symbol_table, name, cmp_by_name);
	if (bs)
	{
		printf("removing symbol %s\n", bs->name);
		free(bs->name);
		free(bs);
		return 0;
	}

	return -2;
}

///////////////////////////////////////////
unsigned int backend_section_count(backend_object* obj)
{
   if (!obj->section_table)
   {
      //printf("No section table yet\n");
      return 0;
   }
   return ll_size(obj->section_table);
}

backend_section* backend_add_section(backend_object* obj, char* name, unsigned long size, unsigned long address, char* data, unsigned int entry_size, unsigned int alignment, unsigned long flags)
{
   if (!obj->section_table)
      obj->section_table = ll_init();

   backend_section* s = malloc(sizeof(backend_section));
	if (!s)
		return NULL;

	//s->index = index;
	//if (index == 0)
	//	s->index = ll_size(obj->section_table) + 1; // index number is 1-based
   s->name = strdup(name);
   s->size = size;
   s->address = address;
   s->flags = flags;
	s->entry_size = entry_size;
   s->data = data;
	s->alignment = alignment;
   //printf("Adding section %s size:%i address:0x%lx entry size: %i flags:0x%x alignment %i\n", s->name, s->size, s->address, s->entry_size, s->flags, s->alignment);
   ll_add(obj->section_table, s);
   //printf("There are %i sections\n", backend_section_count(obj));
   return s;
}

backend_section* backend_get_section_by_index(backend_object* obj, unsigned int index)
{
	int i=1;
   for (const list_node* iter=ll_iter_start(obj->section_table); iter != NULL; iter=iter->next)
   {
      backend_section* sec = iter->val;
		//printf("++ %i %s\n", sec->index, sec->name);
      if (i++ == index)
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

int backend_get_section_index_by_name(backend_object* obj, const char* name)
{
	int index = 0;

	if (!obj || !name || !obj->section_table)
		return -1;

   for (const list_node* iter=ll_iter_start(obj->section_table); iter != NULL; iter=iter->next)
   {
      backend_section* sec = iter->val;
      if (!strcmp(name, sec->name))
         return index+1;
		index++;
   }
   return -1;
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
	//printf("backend_destructor\n");
   // destroy the symbol table
   if (obj->symbol_table)
   {
      backend_symbol* s = ll_pop(obj->symbol_table);
      while (s)
      {
         //printf("Popped %s\n", s->name);
         free(s->name);
         free(s);
         s = ll_pop(obj->symbol_table);
      }
   }

	if (obj->section_table)
   {
      backend_section* sec = ll_pop(obj->section_table);
		while (sec)
		{
         free(sec->name);
         free(sec->data);
			free(sec);
			sec = ll_pop(obj->section_table);
		}
   }

   if (obj->relocation_table)
   {
		backend_reloc* r = ll_pop(obj->relocation_table);
		while (r)
		{
			free(r);
			r = ll_pop(obj->relocation_table);
		}
	}

   // and finally the object itself
   free(obj);
}

///////////////////////////////////////////
unsigned int backend_relocation_count(backend_object* obj)
{
   if (obj && obj->relocation_table)
		return ll_size(obj->relocation_table);
   else
		return 0;
}

int backend_add_relocation(backend_object* obj, unsigned long offset, backend_reloc_type t, backend_symbol* bs)
{
   if (!obj)
		return -1;

	//printf("add relocation for %s @ 0x%lx sec=%s\n", bs->name, addr, sec?sec->name:NULL);
   if (!obj->relocation_table)
      obj->relocation_table = ll_init();

   backend_reloc* r = malloc(sizeof(backend_reloc));
	r->offset = offset;
   r->type = t;
	r->symbol = bs;
   ll_add(obj->relocation_table, r);
   return 0;
}

backend_reloc* backend_find_reloc_by_offset(backend_object* obj, unsigned long offset)
{
	if (!obj || !obj->relocation_table)
		return NULL;

   for (const list_node* iter=ll_iter_start(obj->relocation_table); iter != NULL; iter=iter->next)
   {
      backend_reloc* rel = iter->val;
		if (rel->offset == offset)
			return rel;
	}

	return NULL;
}

backend_reloc* backend_get_first_reloc(backend_object* obj)
{
	if (!obj || !obj->relocation_table)
		return NULL;
	obj->iter_reloc = ll_iter_start(obj->relocation_table);
	return obj->iter_reloc->val;
}

backend_reloc* backend_get_next_reloc(backend_object* obj)
{
   obj->iter_reloc = obj->iter_reloc->next; 
   if (obj->iter_reloc)
      return obj->iter_reloc->val;
   return NULL;
}

