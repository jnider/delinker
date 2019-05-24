#ifndef _CONFIG__H
#define _CONFIG__H

struct config
{
   int reconstruct_symbols;   // rebuild the symbol table
   int verbose;               // print extra information at runtime
};

extern struct config config;

#endif // _CONFIG__H
