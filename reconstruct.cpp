#include <list>
#include <loader.h>
#include <disasm.h>
#include <cfg.h>
#include <options.h>

extern "C" {
#include "backend.h"
}

struct options options;

/* convert our backend format to their backend format */
static int backend_object_to_Binary(Binary& bin, backend_object *obj)
{
	bin.filename = std::string("Unknown");
	bin.entry    = backend_get_entry_point(obj);
	bin.type_str = std::string("Unknown");

	switch(backend_get_type(obj))
	{
	case OBJECT_TYPE_NONE:
		break;

   case OBJECT_TYPE_PE32:
   case OBJECT_TYPE_PE_ROM:
   case OBJECT_TYPE_PE32PLUS:
		bin.type = Binary::BIN_TYPE_PE;
		break;

   case OBJECT_TYPE_ELF32:
   case OBJECT_TYPE_ELF64:
		bin.type = Binary::BIN_TYPE_ELF;
		break;
	}

	switch(backend_get_arch(obj))
	{
	case OBJECT_ARCH_UNKNOWN:
		bin.arch = Binary::ARCH_NONE;
		bin.bits = 0;
		break;

   case OBJECT_ARCH_ARM:
		bin.arch = Binary::ARCH_ARM;
		bin.bits = 32;
		break;

   case OBJECT_ARCH_ARM64:
		bin.arch = Binary::ARCH_AARCH64;
		bin.bits = 64;
		break;

	case OBJECT_ARCH_X86:
		bin.arch = Binary::ARCH_X86;
		bin.bits = 64;
		break;

   case OBJECT_ARCH_MIPS:
  		bin.arch = Binary::ARCH_MIPS;
		bin.bits = 64;
		break;

   case OBJECT_ARCH_PPC:
  		bin.arch = Binary::ARCH_PPC;
		bin.bits = 64;
		break;
	}

	return 0;
}

/* reconstruct the symbol table by using the Nucleus algorithm */
extern "C" int nucleus_reconstruct_symbols(backend_object *obj)
{
	Binary bin;
	std::list<DisasmSection> disasm;
	CFG cfg;

	options.verbosity           = 0;
	options.warnings            = 1;
	options.only_code_sections  = 1;
	options.allow_privileged    = 0;
	options.summarize_functions = 0;
	options.binary.type     = Binary::BIN_TYPE_AUTO;
	options.binary.arch     = Binary::ARCH_NONE;
	options.binary.base_vma = 0;
	options.strategy_function.score_function  = NULL;
	options.strategy_function.mutate_function = NULL;
	options.strategy_function.select_function = NULL;

	backend_object_to_Binary(bin, obj);

	if (nucleus_disasm(&bin, &disasm) < 0)
		return 1;

	if (cfg.make_cfg(&bin, &disasm) < 0)
		return 1;

	cfg.print_functions(stdout);

	return 0;
}

