#include "backend.h"
#include <stdio.h>

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
   printf("backend_register 0x%x\n", be);
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
