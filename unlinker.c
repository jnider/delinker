/* J.Nider 27/07/2017
I tried for so long to get BFD to work, but it is just not built well enough
to be used for other tasks. There are too many format-specific flags and
behaviours that just make life difficult, which is why I am writing my own
backend from scratch. */

/* The idea of the program is simple - read in a fully linked executable,
and write out a set of unlinked .o files that can be relinked later.*/

#include <stdio.h>
#include <getopt.h>
#include "backend.h"

enum error_codes
{
   ERR_NONE,
   ERR_BAD_FILE,
   ERR_BAD_FORMAT,
   ERR_NO_SYMS,
   ERR_NO_SYMS_AFTER_RECONSTRUCT
};

static struct option options[] =
{
  {"output-target", required_argument, 0, 'O'},
  {"reconstruct-symbols", no_argument, 0, 'R'},
  {0, no_argument, 0, 0}
};

struct config
{
   int reconstruct_symbols;
} config;

static void
usage(void)
{
   fprintf(stderr, "Unlinker performs the opposite action to 'ld'. It accepts a binary executable as input, and\n");
   fprintf(stderr, "creates a set of .o files that can be relinked.\n");
   fprintf(stderr, "unlinker <input file>\n");
}

static int reconstruct_symbols(backend_object* obj)
{
   return 0;
}

static int
unlink_file(const char* input_filename, const char* output_target)
{
   backend_object* obj = backend_read(input_filename);

   if (backend_symbol_count(obj) == 0)
   {
      if (config.reconstruct_symbols == 0)
         return -ERR_NO_SYMS;
      else
      {
         reconstruct_symbols(obj);
         if (backend_symbol_count(obj) == 0)
            return -ERR_NO_SYMS_AFTER_RECONSTRUCT;
      }
   }

   // if the output target is not specified, use the input target
   // get the filenames from the input symbol table
      /* iterate through all sections of the input file until we find the text section */
   /* iterate over all symbols in the input table */
      // if the symbol name ends in .c open a corresponding .o for it
      //strcpy(output_filename, symbol->name);
      //printf("Creating file %s\n", output_filename);
      //int len = strlen(output_filename);
      //if (output_filename[len-2] != '.' || output_filename[len-1] != 'c')
      //   continue;
   
      //output_filename[len-1] = 'o';
      //printf("Creating file %s\n", output_filename);
      // create the sections and copy the symbols
            // if the output section doesn't already exist, create it
            // add function symbols to the output symbol table
      // set the base address of the symbols to 0
      // write data to file
}

int
main (int argc, char *argv[])
{
   int status = 0;
   char *input_filename = NULL;
   char *output_target = NULL;

   if (argc < 2)
   {
      usage();
      return -1;
   }

   char c;
   while ((c = getopt_long (argc, argv, "O:R",
          options, (int *) 0)) != EOF)
   {
      switch (c)
      {
      case 'O':
         output_target = optarg;
         break;
      case 'R':
         config.reconstruct_symbols = 1;
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

   backend_init();

   int ret = unlink_file(input_filename, output_target);
   switch (ret)
   {
   case -ERR_BAD_FILE:
      printf("Can't open input file %s\n", input_filename);
      break;
   case -ERR_BAD_FORMAT:
      printf("Unexpected input file format\n");
      break;
   case -ERR_NO_SYMS:
      printf("No symbols found - try again with --reconstruct-symbols\n");
      break;
   case -ERR_NO_SYMS_AFTER_RECONSTRUCT:
      printf("No symbols found even after attempting to recreate them - maybe the code section is empty?\n");
      break;
   }

   return status;
}
