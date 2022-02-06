#include "capstone/capstone.h"
#include "backend.h"
#include "reloc.h"

#ifdef DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT //
#endif

void reloc_x86_16(backend_object* obj, backend_section* sec, csh cs_dis, cs_insn *cs_ins)
{
	const uint8_t *pc = sec->data;
	uint64_t pc_addr = sec->address;
	size_t n = sec->size;

	DEBUG_PRINT("Disassembling from 0x%lx to 0x%lx\n", sec->address, sec->address + sec->size);
	while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins))
	{
		unsigned int offset;
		unsigned int val;
		unsigned short *val_ptr=NULL;
		short *val_rel_ptr=NULL;
		unsigned short *val_ptr_seg=NULL;
		unsigned int *val_ptr_i=NULL;
		backend_symbol *bs=NULL;
		int opcode_size;

		switch (cs_ins->id)
		{
		case X86_INS_CALL:
			// e8 82 00             	call   264 <fn000264>
			// ff 16 d0 53          	call   *0x53d0
			if (cs_ins->size == 4 && cs_ins->bytes[0] == 0xff && cs_ins->bytes[1] == 0x16) 
			{
				val_ptr = (unsigned short*)(pc - 2);
				val = *val_ptr;
				offset = cs_ins->address+1;
			}
			else if (cs_ins->size == 3 && cs_ins->bytes[0] == 0xe8)
			{
				// This is a relative call, which gets replaced by a reloc so the functions
				// are independent in terms of size and location (can be reordered during link)
				val_rel_ptr = (short*)(pc - 2);
				val_ptr = (unsigned short*)(val_rel_ptr);
				val = *val_rel_ptr + pc_addr;
				offset = cs_ins->address+1;
			}
			else if (cs_ins->size == 5 && cs_ins->bytes[0] == 0x9a)
			{
				val_ptr = (unsigned short*)(pc - 4);
				val = *val_ptr;
				offset = cs_ins->address+1;
			}
			if (val_ptr)
			{
				//DEBUG_PRINT("creating relocation: val=%x val_ptr=%p\n", val, val_ptr);
				if (create_reloc(obj, RELOC_TYPE_OFFSET, val, offset, RELOC_HINT_CALL) == 0)
					*val_ptr = 0;
				else
					printf("Error creating relocation @ 0x%lx: val=%x\n", pc_addr, val);
			}
			break;

		case X86_INS_LCALL:
			// 9a 1b 03 00 00       	lcall  $0x0,$0x31b
			if (cs_ins->size == 5 && cs_ins->bytes[0] == 0x9a)
			{
				val_ptr_i = (unsigned int*)(pc - 4);
				val_ptr_seg = (unsigned short*)(pc - 2);
				val_ptr = (unsigned short*)(pc - 4);
				val = (*val_ptr_seg << 4) + *val_ptr;
				offset = cs_ins->address+1;
			}
			if (val_ptr_i)
			{
				if (create_reloc(obj, RELOC_TYPE_OFFSET, val, offset, RELOC_HINT_CALL) == 0)
					*val_ptr_i = 0;
				else
					printf("Error creating relocation @ 0x%lx: val=%x\n", pc_addr, val);
			}
			break;

		case X86_INS_JMP:
			if (cs_ins->size == 3 && cs_ins->bytes[0] == 0xe9)
			{
				// This is a relative call, which may need a reloc if it jumps outside of the current function
				val_rel_ptr = (short*)(pc - 2);
				val_ptr = (unsigned short*)(val_rel_ptr);
				val = *val_rel_ptr + pc_addr;
				offset = cs_ins->address+1;
				bs = backend_find_symbol_by_val_type(obj, pc_addr-cs_ins->size, SYMBOL_TYPE_FUNCTION);
				if (val >= bs->val + bs->size)
				{
					printf("[0x%lx]:You are in function %s, jumping to 0x%x\n", cs_ins->address, bs->name, val);
					if (create_reloc(obj, RELOC_TYPE_OFFSET, val, offset, RELOC_HINT_JUMP) == 0)
						*val_ptr = 0;
					else
						printf("Error creating relocation @ 0x%lx: val=%x\n", pc_addr, val);
				}
			}
			break;

		case X86_INS_MOV:
			// a1 1c 73             	mov    0x731c,%ax
			// a2 c6 64             	mov    %al,0x64c6
			// a3 24 71             	mov    %ax,0x7124
			// c6 06 c1 64 01       	movb   $0x1,0x64c1
			// c7 06 c0 69 0f 52    	movw   $0x520f,0x69c0
			if (cs_ins->size == 3 &&
				(cs_ins->bytes[0] == 0xa1 ||
				cs_ins->bytes[0] == 0xa2 ||
				cs_ins->bytes[0] == 0xa3))
			{
				val_ptr = (unsigned short*)(pc - 2);
				val = *val_ptr + pc_addr;
				offset = cs_ins->address+1;
			}
			else if (cs_ins->size == 5 && cs_ins->bytes[0] == 0xc6 && cs_ins->bytes[1] == 0x06)
			{
				val_ptr = (unsigned short*)(pc - 3);
				val = *val_ptr + pc_addr;
				offset = cs_ins->address+2;
			}
			else if (cs_ins->size == 6 && cs_ins->bytes[0] == 0xc7 && cs_ins->bytes[1] == 0x06)
			{
				val_ptr = (unsigned short*)(pc - 4);
				val = *val_ptr + pc_addr;
				offset = cs_ins->address+2;
			}
			if (val_ptr)
			{
				if (create_reloc(obj, RELOC_TYPE_OFFSET, val, offset, RELOC_HINT_NONE) == 0)
					*val_ptr = 0;
				else
					printf("Error creating relocation @ 0x%lx: val=%x\n", pc_addr, val);
			}
			break;
		}
	}
}

void reloc_x86_32(backend_object* obj, backend_section* sec, csh cs_dis, cs_insn *cs_ins)
{
	const uint8_t *pc = sec->data;
	uint64_t pc_addr = sec->address;
	size_t n = sec->size;

	printf("Disassembling from 0x%lx to 0x%lx\n", sec->address, sec->address + sec->size);
	while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins))
	{
		long val;
		int* val_ptr=0;
		backend_symbol *bs=NULL;
		int opcode_size;

		switch (cs_ins->id)
		{
  		//402345:	ff 34 85 d0 80 40 00 	pushl  0x4080d0(,%eax,4)

		// loading a data address:  mov instruction with a 32-bit immediate
		case X86_INS_MOV:
			// 89 35 ac af 40 00    	mov    %esi,0x40afac
			// 8a 88 40 80 40 00    	mov    0x408040(%eax),%cl
			// 8b 15 34 80 40 00    	mov    0x408034,%edx
			// a1 dc ac 40 00       	mov    0x40acdc,%eax
			// a3 9c af 40 00       	mov    %eax,0x40af9c
			// b8 98 81 40 00       	mov    $0x408198,%eax
			// be 98 82 40 00       	mov    $0x408298,%esi
			// bf a0 af 40 00       	mov    $0x40afa0,%edi
			// c7 05 ac af 40 00 01 	movl   $0x1,0x40afac
			if (cs_ins->size == 6 && (cs_ins->bytes[0] == 0x89 ||
									cs_ins->bytes[0] == 0x8a  ||
									cs_ins->bytes[0] == 0x8b))
				val_ptr = (int*)(cs_ins->bytes + 2);
			else if (cs_ins->size == 5 && (cs_ins->bytes[0] == 0xa1 ||
									cs_ins->bytes[0] == 0xa3  ||
									cs_ins->bytes[0] == 0xb8 ||
									cs_ins->bytes[0] == 0xbe ||
									cs_ins->bytes[0] == 0xbf))
				val_ptr = (int*)(cs_ins->bytes + 1);
			else if (cs_ins->size == 7 && (cs_ins->bytes[0] == 0xc7))
				val_ptr = (int*)(cs_ins->bytes + 2);

			if (val_ptr)
			{
				if (create_reloc(obj, RELOC_TYPE_OFFSET, *val_ptr, cs_ins->address+2, RELOC_HINT_NONE) == 0)
					*val_ptr = 0;
			}
			break;

		case X86_INS_JMP:
			// ff 25 98 62 45 00       jmp    *0x456298
			// e8 00 00 00 00          call   33 <fn000020+0x13>
			// e9 ae cc ff ff          jmp    8048660 <malloc@plt>
			if (cs_ins->size == 6 && (cs_ins->bytes[0] == 0xFF)) 
			{
				val_ptr = (int*)(cs_ins->bytes + 2);
				val = *val_ptr;
			}
			else if (cs_ins->size == 5 && (cs_ins->bytes[0] == 0xe8 || cs_ins->bytes[0] == 0xe9))
			{
				// this instruction uses a relative offset, so to get the absolute address, add the:
				// current instruction offset + length of current instruction + call offset
				val_ptr = (int*)(cs_ins->bytes + 1);
				val = cs_ins->address + cs_ins->size + *val_ptr;
			}
			if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+1, RELOC_HINT_JUMP) == 0)
				break;
				//*val_ptr = 0;
			break;

		// callq calls a function with 1 byte opcode and signed 32-bit relative offset
		case X86_INS_CALL:
			//printf("Found call @ 0x%lx to 0x%lx\n", sec_text->address + addr, val); 
			break;
		}
	}
}

void reloc_x86_64(backend_object* obj, backend_section* sec, csh cs_dis, cs_insn *cs_ins)
{
	const uint8_t *pc = sec->data;
	uint64_t pc_addr = sec->address;
	size_t n = sec->size;
	int *val_ptr;

	//printf("x86_64: Disassembling from 0x%lx to 0x%lx\n", sec->address, sec->address + sec->size);

	while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins))
	{
		int val=0;
		//unsigned int offset = addr + 1; // offset of the operand
		backend_symbol *bs=NULL;
		int opcode_size;

		//printf("ins: %s@0x%lx (0x%x) len=%i\n", cs_ins->mnemonic, cs_ins->address, cs_ins->bytes[0], cs_ins->size);
		switch (cs_ins->id)
		{
		case X86_INS_LEA:
			// 48 8d 3d 89 0f 00 00 	lea    0xf89(%rip),%rdi
			if (cs_ins->size == 7 && cs_ins->bytes[0] == 0x48 && cs_ins->bytes[1] == 0x8d &&
				(cs_ins->bytes[2] == 0x3d || cs_ins->bytes[2] == 0x35 || cs_ins->bytes[2] == 0x0d || cs_ins->bytes[2] == 0x05)) // rsi rdi rcx rax
			{
				val_ptr = (int*)((char*)pc - cs_ins->size + 3);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+3, RELOC_HINT_NONE) == 0)
					*val_ptr = 0;
			}
			break;

		case X86_INS_MOV:
			// 48 8b 05 9b 99 5f 00		mov    0x5f999b(%rip),%rax
			if (cs_ins->size == 7 && cs_ins->bytes[0] == 0x48 && cs_ins->bytes[1] == 0x8b &&
				(cs_ins->bytes[2] == 0x05 || cs_ins->bytes[2] == 0x0d || cs_ins->bytes[2] == 0x15 ||
				cs_ins->bytes[2] == 0x35 || cs_ins->bytes[2] == 0x3d))
			{
				val_ptr = (int*)((char*)pc - cs_ins->size + 3);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+3, RELOC_HINT_NONE) == 0)
					*val_ptr = 0;
			}
			// 48 89 05 87 39 10 00 	mov    %rax,0x103987(%rip)
			else if (cs_ins->size == 7 && cs_ins->bytes[0] == 0x48 && cs_ins->bytes[1] == 0x89 &&
				(cs_ins->bytes[2] == 0x05 || cs_ins->bytes[2] == 0x0d || cs_ins->bytes[2] == 0x15))
			{
				val_ptr = (int*)((char*)pc - cs_ins->size + 3);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+3, RELOC_HINT_NONE) == 0)
					*val_ptr = 0;
			}

			// b8 02 00 1f bb				mov    $0xbb1f0002,%eax
			// bf 43 08 40 00       	mov    $0x400843,%edi
			else if (cs_ins->size == 5 && cs_ins->bytes[0] == 0xbf)
			{
				val_ptr = (int*)((char*)pc - cs_ins->size + 1);
				val = *val_ptr;
				if (create_reloc(obj, RELOC_TYPE_OFFSET, val, cs_ins->address+1, RELOC_HINT_NONE) == 0)
					*val_ptr = 0;
			}
			break;

		case X86_INS_MOVQ:
			//48 c7 05 c9 f7 10 00 01 00 00 00 	movq   $0x1,0x10f7c9(%rip)
			if (cs_ins->size == 11 && cs_ins->bytes[0] == 0x48 && cs_ins->bytes[1] == 0xc7 &&
				(cs_ins->bytes[2] == 0x05))
			{
				val_ptr = (int*)((char*)pc - cs_ins->size + 3);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+3, RELOC_HINT_NONE) == 0)
					*val_ptr = 0;
			}
			break;

		case X86_INS_CALL:
    		//	e8 d6 fe ff ff       	callq  1030 <printf@plt> 
			// even though e8 is a relative call, it may call into the PLT
			// which needs to be replaced since the PLT may not survive
			if (cs_ins->size == 5 && cs_ins->bytes[0] == 0xe8)
			{
				val_ptr = (int*)((char*)pc - cs_ins->size + 1);
				val = cs_ins->address + *val_ptr + cs_ins->size;
				//printf("Found CALL E8 to 0x%x @ 0x%lx\n", val, cs_ins->address);
				if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+1, RELOC_HINT_CALL) == 0)
					*val_ptr = 0;
			}
    		//	ff 15 66 2f 00 00    	callq  *0x2f66(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
			else if (cs_ins->size == 6 && cs_ins->bytes[0] == 0xff)
			{
				//val_ptr = (unsigned int*)(cs_ins->bytes + 2);
				//printf("Found CALL FF to 0x%x\n", *val_ptr);
			}

			// create a relocation for a call instruction
			break;

		case X86_INS_VMOVAPD:
			// c5 fd 28 1d f7 3d 00 00		vmovapd 0x3df7(%rip),%ymm3
		case X86_INS_VMOVSD:
			// c5 fb 10 05 71 3d 00 00		vmovsd 0x3d71(%rip),%xmm0
			// c5 fb 11 86 90 c1 ff ff  	vmovsd %xmm0,-0x3e70(%rsi)
		case X86_INS_VMULSD:
			// c5 eb 59 3d 7d 2f 00 00 	vmulsd 0x2f7d(%rip),%xmm2,%xmm7
			val_ptr = (int*)((char*)pc - cs_ins->size + 4);
			val = cs_ins->address + *val_ptr + cs_ins->size;
			//printf("Found VMOVAPD to 0x%x @ 0x%lx\n", val, cs_ins->address);
			if (create_reloc(obj, RELOC_TYPE_PC_RELATIVE, val, cs_ins->address+4, RELOC_HINT_NONE) == 0)
				*val_ptr = 0;
			break;

		//case CALL: // opcode FF
		// break;
		}

	}
}
