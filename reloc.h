#ifndef _RELOC__H
#define _RELOC__H

enum reloc_hint
{
	RELOC_HINT_NONE,
	RELOC_HINT_CALL,
	RELOC_HINT_JUMP,
};

int create_reloc(backend_object *obj, backend_reloc_type t, unsigned int val, int offset, unsigned int hint);

#endif // _RELOC__H
