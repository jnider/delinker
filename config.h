#ifndef _CONFIG__H
#define _CONFIG__H

enum reconstructor_functions
{
	RECONSTRUCTOR_BUILTIN,
	RECONSTRUCTOR_NUCLEUS
};

struct config
{
   int reconstruct_symbols;   // rebuild the symbol table
   int reconstructor;   		// function to use for symbol reconstruction (see RECONSTRUCTOR_)
   int verbose;               // print extra information at runtime
	bool symbol_per_file;		// write one symbol in each file - this is really useful
										// when planning to make modifications before relinking.
	linked_list *ignore_list;	// List of symbols to ignore
};

// make the config globally accessible
extern struct config config;

#endif // _CONFIG__H
