#include <stdio.h>
#include "backend.h"
#include "ll.h"

#define MAX_BACKENDS 3
#define DECLARE_BACKEND(_x) extern int _x##_init()

DECLARE_BACKEND(pe);

static backend_ops* backend[MAX_BACKENDS] = {0};
static int num_backends;

int backend_init(void)
{
   pe_init();
}

void backend_register(backend_ops* be)
{
   if (num_backends < MAX_BACKENDS)
      backend[num_backends++] = be;
   printf("num backends %i\n", num_backends);
}

backend_object* backend_read(const char* filename)
{
   printf("backend_read\n");
   // run through all backends until we find one that returns an object
   for (int i=0; i < num_backends; i++)
   {
      backend_object* obj = backend[i]->read(filename);
      if (obj)
         return obj;
   }
   return 0;
}

int backend_write(const char* filename, backend_object* obj)
{
   return 0;
}

void backend_set_type(backend_object* obj, backend_type t)
{
   obj->type = t;
}

unsigned int backend_symbol_count(backend_object* obj)
{
   if (obj->symbol_table)
      return ll_size(obj->symbol_table);
   else
      return 0;
}

int backend_add_symbol(backend_object* obj, const char* name, unsigned int val, unsigned int type, unsigned int flags)
{
   if (!obj->symbol_table)
      obj->symbol_table = ll_init();
}

