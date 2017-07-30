/* Generic backend header file

Define the interface for target-specific backend implementations, as well as the
public functions for talking to backends */

typedef enum backend_type
{
   OBJECT_TYPE_NONE,
   OBJECT_TYPE_PE32
} backend_type;

typedef struct backend_section
{
   unsigned int start;
   unsigned int length;
   unsigned int flags;
   char* data;
} backend_section;

typedef struct backend_object
{
   backend_type type;
   backend_section* sections;
   unsigned int num_sections;
} backend_object;

typedef struct backend_ops
{
   backend_object* (*read)(const char* filename);
} backend_ops;

/* initialize the library for use - don't call any functions before this one */
int backend_init(void);

void backend_register();
backend_object* backend_read(const char* filename);
int backend_write(const char* filename, backend_object* obj);
void backend_set_type(backend_object* obj, backend_type t);
