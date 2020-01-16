# ----------------------------------------------------------------------
# Processor module template script
# (c) Hex-Rays
import sys
import idaapi
import ida_frame 
from idaapi import *
from ida_bytes import *
from ida_ua import *
from ida_idp import *
from ida_auto import *
from ida_nalt import *
from ida_funcs import *
from ida_lines import *
from ida_problems import *
from ida_offset import *
from ida_segment import *
from ida_name import *
from ida_netnode import *
from ida_xref import *
from ida_idaapi import *
import ida_frame
import idc





# ----------------------------------------------------------------------
class dwarf2_processor_t(idaapi.processor_t):

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
		id = 0x8000 + 1

    # Processor features
		flag = PR_ASSEMBLE | PR_USE64 | PRN_HEX | PR_RNAMESOK

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
		cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
		dnbits = 8

		psnames = ['dwarf2']

		plnames = ['Dwarf Processor Module 2nd Edition']

		reg_names = [ "R0",  	"R1", 	"R2", 	"R3", 	"R4", 	"R5", 	"R6", 	"R8", 	"R9", 	"R10", 	"R11", 	"R12", 	"R13", 	"R14", 	"R15", 	"R16", 	"R17", 	"R18", 	"R19", 	"R20", 	"R21", 	"R22", 	"R23", 	"R24", 	"R25", 	"R26", 	"R27", 	"R28", 	"R29", 	"R30", 	"R31",  	"CDS" 	] 


		reg_first_sreg = 33 # Premier registre de segment   
		reg_last_sreg  = 33 # Dernier registre de segment 

		# size of a segment register in bytes
		segreg_size = 0 # Pas 

		# Le code et la donnees partagent le meme segment 
		reg_code_sreg = 33 
		reg_data_sreg = 33

		
		codestart = [] 

    # Array of 'return' instruction opcodes (optional)
		retcodes = [] 


# Array of instructions. Since this is only a template,
# this list will be extremely limited.
		instruc = [
		{'name': 'ADDR', 'feature': CF_USE1, 'cmt' : 'push addr (from imm) depending on the host arch', 'stack_inc' : 1 }, 
		{'name': 'DEREF', 'feature':0, 'cmt': 'pop addr, push *addr', 'stack_inc' : 0}, 
		{'name': 'LIT1', 'feature': CF_USE1, 'cmt': 'push 1byte unsigned', 'stack_inc' :1}, 
		{'name': 'LIT1S', 'feature': CF_USE1, 'cmt' : 'push 1byte signed', 'stack_inc' :1}, 
		{'name': 'LIT2', 'feature': CF_USE1, 'cmt' : 'push 2bytes unsigned', 'stack_inc' :1}, 
		{'name': 'LIT2S', 'feature': CF_USE1, 'cmt' : 'push 2bytes singed', 'stack_inc' :1}, 
		{'name': 'LIT4', 'feature': CF_USE1, 'cmt' : 'push 4bytes unsigned', 'stack_inc' :1}, 
		{'name': 'LIT4S', 'feature': CF_USE1, 'cmt' : 'push 4bytes signed', 'stack_inc' :1}, 
		{'name': 'LIT8', 'feature': CF_USE1, 'cmt': 'push 8bytes unsigned', 'stack_inc' :1}, 
		{'name': 'LIT8S', 'feature': CF_USE1, 'cmt' : 'push 8bytes signed', 'stack_inc' :1}, 
		{'name': 'LITULEB', 'feature': CF_USE1, 'cmt': 'push uleb128 constant (maybe encode it before?)', 'stack_inc' :1}, 
		{'name': 'LITSLEB', 'feature': CF_USE1, 'cmt': 'push sleb128 constant (maybe encode it before?)', 'stack_inc' :1}, 
		{'name': 'DUP', 'feature':0, 'cmt' : 'duplicate (equivalent to push stack[0]', 'stack_inc' :1}, 
		{'name': 'DROP', 'feature':0, 'cmt' : 'drop first value (pop into the void)', 'stack_inc' :-1}, 
		{'name': 'OVER', 'feature':0, 'cmt' : 'push second top value (equivalent to push stack[1]', 'stack_inc' :1}, 
		{'name': 'PICK', 'feature': CF_USE1, 'cmt': 'take the imm ([0:FF]) and push stack[imm]', 'stack_inc' :1}, 
		{'name': 'SWAP', 'feature':0, 'cmt': ' STACK[0] = STACK[1] & STACK[1] = STACK[0]', 'stack_inc' : 0}, 
		{'name': 'ROT', 'feature':0, 'cmt' :'STACK[0] = STACK[2] & STACK[1] = STACK[0] & STACK[2] == STACK[0]', 'stack_inc' :0}, 
		{'name': 'XDEREF', 'feature':0, 'cmt' : 'pop two values (ADDR + ADDR_SPACE_ID) and push the results', 'stack_inc' :-1}, 
		{'name': 'ABS', 'feature':0, 'cmt' : 'pop value and push abs(value)', 'stack_inc' :0}, 
		{'name': 'AND', 'feature':0, 'cmt' : 'pop two values v1,v2 then push v1 & v2 result', 'stack_inc' :-1}, 
		{'name': 'DIV', 'feature':0, 'cmt' : 'pop two values v1,v2 then push v1 / v2 result', 'stack_inc' :-1 }, 
		{'name': 'MINUS', 'feature':0, 'cmt' : 'pop two values v1,v2 then push v1 - v2 result', 'stack_inc' :-1}, 
		{'name': 'MOD', 'feature':0, 'cmt' : 'pop v1,v2;  push v1 mod v2', 'stack_inc' :-1}, 
		{'name': 'MUL', 'feature':0, 'cmt' : 'mul v1,v2; push v1*v2', 'stack_inc' :-1}, 
		{'name': 'NEG', 'feature':0, 'cmt' : 'pop v1; push neg(v1)', 'stack_inc' :0}, 
		{'name': 'NOT', 'feature':0, 'cmt' : 'pop v1 ; push  ~v1', 'stack_inc' :0}, 
		{'name': 'OR', 'feature':0, 'cmt' : 'pop v1,v2 ; push v1 or v2', 'stack_inc' :-1},
		{'name': 'PLUS', 'feature':0, 'cmt' : 'pop v1,v2; push v1+v2', 'stack_inc' :-1}, 
		{'name': 'PLUSCONST', 'feature': CF_USE1, 'cmt': 'pop v; push v+imm', 'stack_inc' :0},
		{'name': 'SHL', 'feature':0, 'cmt' : 'pop v ; push v<<1;', 'stack_inc' :0}, 
		{'name': 'SHR', 'feature':0, 'cmt' : 'pop v; push v>>1;', 'stack_inc' :0}, 
		{'name': 'SHRA', 'feature':0, 'cmt' : 'pop v1; pop v2 push v2>>v1 (arithmetic)', 'stack_inc' :-1}, 
		{'name': 'XOR', 'feature':0, 'cmt' : 'pop v1,v2; push v1~v2', 'stack_inc' :-1}, 
		{'name': 'SKIP', 'feature': CF_USE1 | CF_STOP, 'cmt' : 'jmp imm', 'stack_inc' :0}, 
		{'name': 'BRANCH', 'feature': CF_USE1, 'cmt' : 'pop v ; if v != 0 jmp imm', 'stack_inc' :0}, 
		{'name': 'EQ', 'feature':0, 'cmt' : 'pop v1,v2; push 1 if v1==v2 else push 0', 'stack_inc' :-1}, 
		{'name': 'GE', 'feature':0, 'cmt' : 'pop v1,v2; push 1 if v1>=v2 else push 0', 'stack_inc' :-1}, 
		{'name': 'GT', 'feature':0, 'cmt' : 'pop v1,v2; push 1 if v1>v2 else push 0', 'stack_inc' :-1}, 
		{'name': 'LE', 'feature':0, 'cmt' : 'pop v1,v2; push 1 if v1<=v2 else push 0', 'stack_inc' :-1}, 
		{'name': 'LT', 'feature':0, 'cmt' : 'pop v1,v2; push 1 if v1<v2 else push 0', 'stack_inc' :-1}, 
		{'name': 'NE', 'feature':0, 'cmt' : 'pop v1,v2; push 1 if v1!=v2 else push 0', 'stack_inc' :-1}, 
		{'name': 'LITn', 'feature' : CF_USE1, 'cmt': 'encode unsigned litteral value from 0..31 and push it', 'stack_inc' :1}, 
		{'name': 'REGn', 'feature': CF_USE1, 'cmt' : 'push operations  encode  the  names  of  up  to  32  registers,  numbered  from  0through 31, inclusive.', 'stack_inc' :1 }, 
		{'name': 'BREG', 'feature': CF_USE1, 'cmt' : 'push value content by register n + sleb128 imm ', 'stack_inc' :1}, 
		{'name': 'REGX', 'feature': CF_USE1, 'cmt' : '(probably) push the encoded name of register n where n is the encoded 128 identifier', 'stack_inc' :1}, 
		{'name': 'FBREG', 'feature': CF_USE1,'cmt' : 'push imm (sleb128) + DW_AT_frame_bas', 'stack_inc' :1},  
		{'name': 'BREGX', 'feature': CF_USE1 | CF_USE2, 'cmt' : 'push value content by reg encoded in uleb128 + sleb128 imm2', 'stack_inc' :1 }, 
		{'name': 'PIECE', 'feature': CF_USE1, 'cmt': 'the imm uleb128 imm is giving the size of object referenced by address on top of stack', 'stack_inc' :1}, 
		{'name': 'DEREF_SIZE', 'feature': CF_USE1, 'cmt' : 'pop a value threat it like an address, but size is specified by imm(1byte) and data is zero extended to the len of address space', 'stack_inc' :0}, 
		{'name': 'XDEREF_SIZE', 'feature': CF_USE1, 'cmt' : 'like xderef but data size if specified by imm1 and ADDR_SPACE_ID by second poped value', 'stack_inc' :-1}, 
		{'name': 'NOP', 'feature':0, 'cmt': 'nopnop', 'stack_inc' :0}, 
		{'name': 'LOUSER', 'feature':0, 'cmt': 'rtfm', 'stack_inc' :0}, 
		{'name': 'HIUSER', 'feature':0, 'cmt': 'rtfm', 'stack_inc' :0}
		]

		# icode of the first instruction
		instruc_start = 0

		# icode of the last instruction + 1
		instruc_end = len(instruc)

		# Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
		tbyte_size = 0

		real_width = (0, 7, 15, 0)

		icode_return = 0xFF

		assembler = {
				# flag
		'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

		# user defined flags (local only for IDP) (optional)
		'uflag' : 0,

		# Assembler name (displayed in menus)
		'name': "My dwarf  module bytecode assembler",

		# array of automatically generated header lines they appear at the start of disassembled text (optional)
		'header': ["Line1", "Line2"],

		# org directive
		'origin': "org",

		# end directive
		'end': "end",

		# comment string (see also cmnt2)
		'cmnt': ";",

		# ASCII string delimiter
		'ascsep': "\"",

		# ASCII char constant delimiter
		'accsep': "'",

		# ASCII special chars (they can't appear in character and ascii constants)
		'esccodes': "\"'",

		#
		#      Data representation (db,dw,...):
		#
		# ASCII string directive
		'a_ascii': "db",

		# byte directive
		'a_byte': "db",

		# word directive
		'a_word': "dw",

		# remove if not allowed
		'a_dword': "dd",

		# remove if not allowed
		'a_qword': "dq",



		# double; 8bytes; NULL if not allowed
		'a_double': "dq",

		# long double;    NULL if not allowed
		'a_tbyte': "dt",


		# array keyword. the following
		# sequences may appear:
		#      #h - header
		#      #d - size
		#      #v - value
		#      #s(b,w,l,q,f,d,o) - size specifiers
		#                        for byte,word,
		#                            dword,qword,
		#                            float,double,oword
		'a_dups': "#d dup(#v)",

		# uninitialized data directive (should include '%s' for the size of data)
		'a_bss': "%s dup ?",

		# 'equ' Used if AS_UNEQU is set (optional)
		'a_equ': ".equ",

		# 'seg ' prefix (example: push seg seg001)
		'a_seg': "seg",

		# current IP (instruction pointer) symbol in assembler
		'a_curip': "$",

		# "public" name keyword. NULL-gen default, ""-do not generate
		'a_public': "public",

		# "weak"   name keyword. NULL-gen default, ""-do not generate
		'a_weak': "",

		# "extrn"  name keyword
		'a_extrn': "extrn",

		# "comm" (communal variable)
		'a_comdef': "",

		# "align" keyword
		'a_align': "align",

		# Left and right braces used in complex expressions
		'lbrace': "(",
		'rbrace': ")",

		# %  mod     assembler time operation
		'a_mod': "%",

		# &  bit and assembler time operation
		'a_band': "&",

		# |  bit or  assembler time operation
		'a_bor': "|",

		# ^  bit xor assembler time operation
		'a_xor': "^",

		# ~  bit not assembler time operation
		'a_bnot': "~",

		# << shift left assembler time operation
		'a_shl': "<<",

		# >> shift right assembler time operation
		'a_shr': ">>",

		# size of type (format string) (optional)
		'a_sizeof_fmt': "size %s",

		'flag2': 0,

		# comment close string (optional)
		# this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
		# then cmnt = "(*" and cmnt2 = "*)"
		'cmnt2': "",

		# low8 operation, should contain %s for the operand (optional fields)
		'low8': "",
		'high8': "",
		'low16': "",
		'high16': "",

		# the include directive (format string) (optional)
		'a_include_fmt': "include %s",

		# if a named item is a structure and displayed  in the verbose (multiline) form then display the name
		# as printf(a_strucname_fmt, typename)
		# (for asms with type checking, e.g. tasm ideal)
		# (optional)
		'a_vstruc_fmt': "",

		# 'rva' keyword for image based offsets (optional)
		# (see nalt.hpp, REFINFO_RVA)
		'a_rva': "rva"
	} # Assembler


		stack_entrysize= 8 # in bytes

		def regname2index(self, regname):
			for idx in xrange(len(self.reg_names)):
				if regname == self.reg_names[idx]:
					return idx
 			return -1
	
			return result


		def get_uleb128(self, insn):
				'''Extract a ULEB128 number'''
				byte = insn.get_next_byte()
				bytecount=0
				# Quick test for single byte ULEB
 				if byte & 0x80:
						bytecount+=1
						result = byte & 0x7f
						shift = 7
						while byte & 0x80:
								byte = insn.get_next_byte()
								result |= (byte & 0x7f) << shift
								shift += 7
						return result,bytecount
				else:
						return byte,1	# Simple one byte ULEB128 value...

		def get_sleb128(self, insn):
				result = 0
				shift = 0
				size = 64
				byte = 0
				bytecount = 0
				while 1:
						bytecount += 1
						byte = insn.get_next_byte()
						result |= (byte & 0x7f) << shift
						shift += 7
						if (byte & 0x80) == 0:
								break
				if (shift < size and (byte & 0x40)):
						result |= - (1 << shift)
				return result,bytecount


		def notify_get_autocmt(self, insn):
				"""
				Get instruction comment. 'insn' describes the instruction in question
				@return: None or the comment string
				"""
				if 'cmt' in self.instruc[insn.itype]:
					return self.instruc[insn.itype]['cmt']

		def add_stkpnt(self, pfn, insn, v):
				"""
				Add stack movment information. 
				Needs to be part of a func
				"""
				if pfn:
						end = insn.ea + insn.size
						ida_frame.add_auto_stkpnt(pfn, end, v)
				else:
					print('[!]Could not add stack information at %s because insn is not part of function'%hex(insn.ea))





		def notify_emu(self, insn):
				"""
				Emulate instruction, create cross-references, plan to analyze
				subsequent instructions, modify flags etc. Upon entrance to this function
				all information about the instruction is in 'insn' structure.
				If zero is returned, the kernel will delete the instruction.
				"""

				try:
				
					if insn.itype == 34: # SKIP
							add_cref(insn.ea, insn.Op1.addr , fl_JN) 
					elif insn.itype == 35: #BRANCH 
							add_cref(insn.ea, insn.Op1.addr , fl_JN) 
							add_cref(insn.ea, insn.ea + insn.size, fl_F)
					else:  
							add_cref(insn.ea, insn.ea + insn.size, fl_F)

					if self.instruc[insn.itype]['stack_inc'] != 0: 
						self.add_stkpnt(get_func(insn.ea),insn,self.stack_entrysize*self.instruc[insn.itype]['stack_inc']) 

				except Exception as e:
					print('[!]Exception in notify_emu: %s'%e.__str__())



				return 1

		def notify_out_operand(self, ctx, op):
				"""
				Generate text representation of an instructon operand.
				This function shouldn't change the database, flags or anything else.
				All these actions should be performed only by u_emu() function.
				The output text is placed in the output buffer initialized with init_output_buffer()
				This function uses out_...() functions from ua.hpp to generate the operand text
				Returns: 1-ok, 0-operand is hidden.
				"""
				try:
					if op.type == o_reg:
							ctx.out_register(self.reg_names[op.reg])
					elif op.type == o_imm:
							ctx.out_value(op, OOFW_IMM)
					elif op.type == o_near:
							ctx.out_name_expr(op, op.addr, BADADDR)
					else:
							return False
				except Exception as e: 
					print('[!]Error in notify_out_operand:%s'%e.__str__()) 

				return True

		def notify_out_insn(self, ctx):
				"""
				Generate text representation of an instruction in 'ctx.insn' structure.
				This function shouldn't change the database, flags or anything else.
				All these actions should be performed only by u_emu() function.
				Returns: nothing
				"""
				try: 
					ctx.out_mnemonic()

					for i in xrange(0, 2):
							op = ctx.insn[i]
							if op.type == o_void:
										break;
							if i > 0:
										ctx.out_symbol(',')
										ctx.out_char(' ')
							ctx.out_one_operand(i)

					ctx.set_gen_cmt()
					ctx.flush_outbuf()
				except:
					print('Error in notify_out_insn') 

		def notify_ana(self, insn):
				"""
				Decodes an instruction into insn
				Returns: insn.size (=the size of the decoded instruction) or zero
				"""
				opcode = insn.get_next_byte()
				if opcode == 0x03:              # ADD
					insn.itype = 0
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_qword
					insn.Op1.value = insn.get_next_qword() #get_64bit(insn.ea+1)
				elif opcode == 0x06:						 # DEREF 
					insn.itype = 1 
				elif opcode == 0x8: 						 # LIT Byte Unsigned  
					insn.itype = 2 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_byte
					insn.Op1.value = insn.get_next_byte()
				elif opcode == 0x9:  					 # LIT Byte Signed
					insn.itype = 3 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_byte
					insn.Op1.value = insn.get_next_byte()
				elif opcode == 0xa: 						# LIT  Word UnSigned
					insn.itype = 4 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_word
					insn.Op1.value = insn.get_next_word()
				elif opcode == 0xb:						# LIT Word Signed 
					insn.itype = 5 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_word
					insn.Op1.value = insn.get_next_word()
				elif opcode == 0xc: 					 # LIT Double Unsigned
					insn.itype = 6 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_dword
					insn.Op1.value = insn.get_next_dword()
				elif opcode == 0xd:  				 # LIT Double Signed
					insn.itype = 7 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_dword
					insn.Op1.value = insn.get_next_dword()
				elif opcode == 0xe: 					# LIT Qword Unsigned 
					insn.itype = 8 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_qword
					insn.Op1.value = insn.get_next_qword()
				elif opcode == 0xf: 				 # LIT Qword Signed 
					insn.itype = 9 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_qword
					insn.Op1.value = insn.get_next_qword()
				elif opcode == 0x10: 			# LIT ULEB128
					insn.itype = 10 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_qword
					val,bconsumed1 = self.get_uleb128(insn)
					insn.value = val 
					insn.size = 1 +bconsumed1
					
				elif opcode == 0x11: 		 # LUT SLEB128
					insn.itype = 11
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_qword
					val,bconsumed1 = self.get_sleb128(insn)
					insn.value = val 
					insn.size = 1 +bconsumed1
					
				elif opcode == 0x12: 		# DUP
					insn.itype = 12 
				elif opcode == 0x13:			#DROP
					insn.itype = 13 
				elif opcode == 0x14:			#OVER
					insn.itype = 14 
				elif opcode == 0x15:			#PICK [0..255] Note DWARF2 only handle 64 stack entries
					insn.itype = 15 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_byte
					insn.Op1.value = insn.get_next_byte() 
				elif opcode == 0x16:			# SWAP 
					insn.itype = 16 
				elif opcode == 0x17:			# ROT
					insn.itype = 17 
				elif opcode == 0x18: 		# XDEREF 
					insn.itype = 18 	
				elif opcode == 0x19:			# ABS
					insn.itype = 19 
				elif opcode == 0x1A:			# AND
					insn.itype = 20 
				elif opcode == 0x1B:			# DIV
					insn.itype = 21
				elif opcode == 0x1C:			# MINUS
					insn.itype = 22 
				elif opcode == 0x1D:
					insn.itype = 23 	# MOD
				elif opcode == 0x1E:
					insn.itype = 24		# MUL 
				elif opcode == 0x1F:
					insn.itype = 25 	# NEG
				elif opcode == 0x20:
					insn.itype = 26 	# NOTT
				elif opcode == 0x21:
					insn.itype = 27   # ORR
				elif opcode == 0x22:
					insn.itype = 28 	# PLUS 
				elif opcode == 0x23: # plus_uconst
					insn.itype = 29 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_qword
					insn.Op1.value = insn.get_next_qword() #TODO : ULEB218
				elif opcode == 0x24:  #shl
					insn.itype = 30 
				elif opcode == 0x25: #shr
					insn.itype = 31 
				elif opcode == 0x26:#shra
					insn.itype = 32 
				elif opcode == 0x27:#xor
					insn.itype = 33 
				elif opcode == 0x2F: #skip
					insn.itype = 34 
					insn.Op1.type = o_near
					insn.Op1.dtype = dt_word
					nea = insn.get_next_word()
					insn.Op1.addr = (insn.ea + nea +3) if (not (nea&0x8000)) else (insn.ea + 3 + (nea - (1<<16))) # 2 + 1 skip insn.size

				elif opcode == 0x28: #branch  
					insn.itype = 35 
					insn.Op1.type = o_near
					insn.Op1.dtype = dt_word
					nea = insn.get_next_word()
					insn.Op1.addr = (insn.ea + nea +3) if (not (nea&0x8000)) else (insn.ea + 3 + (nea - (1<<16))) 

				elif opcode == 0x29:#eq 
					insn.itype = 36 

				elif opcode == 0x2a:#ge
					insn.itype = 37 

				elif opcode == 0x2b:#gt
					insn.itype = 38 

				elif opcode == 0x2c:#le
					insn.itype = 39
				elif opcode == 0x2d:#lt
					insn.itype =40  

				elif opcode == 0x2e:#ne
					insn.itype =41 
				elif opcode in  range(0x30,0x50): #litn 
					insn.itype =42 
					insn.Op1.type = o_reg
					insn.Op1.reg = opcode-0x30 
				elif opcode in  range(0x50,0x70): #regn 
					insn.itype =43
					insn.Op1.type = o_reg
					insn.Op1.reg = opcode-0x50-1
				elif opcode in  range (0x70,0x90) : #breg 
					insn.type=44
					insn.Op1.type = o_reg
					val,bconsumed = self.get_sleb128(insn) 
					print('[*] OpCode 0x%x'%b,' breg value : 0x%x'%val)
					insn.Op1.reg = val
					insn.size=1+bconsumed
					
				elif opcode == 0x90: #breg
					insn.itype = 45
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_tbyte # variable len
					val,bconsumed = self.get_uleb128(insn)
					insn.Op1.value =  val 
					insn.size=1+bconsumed
	
				elif opcode == 0x91:#fbreg
					insn.itype = 46 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_tbyte # variable len
					val,bconsumed = self.get_sleb128(insn)
					insn.Op1.value =  val 
					insn.size=1+bconsumed

				elif opcode == 0x92: #bregx
					insn.itype = 47 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_tbyte # variable len
					val,bconsumed1 = self.get_uleb128(insn)
					insn.Op1.value =  val 
					insn.Op2.type = o_imm
					insn.Op2.dtype = dt_tbyte # variable len
					val,bconsumed2 = self.get_sleb128(insn)
					insn.Op1.value =  val 
					insn.size=1+bconsumed1+bconsumed2
				elif opcode == 0x93: #piece
					insn.itype = 48 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_tbyte # variable len
					val,bconsumed = self.get_uleb128(insn)
					insn.Op1.value =  val 
					insn.size=1+bconsumed
				elif opcode == 0x94: #deref 
					insn.itype = 49 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_byte
					insn.Op1.value = insn.get_next_byte() 
				elif opcode == 0x95: 
					insn.itype = 50 
					insn.Op1.type = o_imm
					insn.Op1.dtype = dt_qword
					insn.Op1.value = insn.get_next_byte() 
				elif opcode == 0x96:
					insn.type=51
				elif opcode == 0xe0:
					insn.itype = 52
				elif opcode == 0xff:
					insn.itype =53 
				else:
					return 0 

				# Return decoded instruction size or zero
				return insn.size

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
		return dwarf2_processor_t()
