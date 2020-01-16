global stk
global MEM_40024C 




def tto_bytes(bytearrayy,endianness):


	
	if str(type(bytearrayy))  != "<class 'bytearray'>" and str(type(bytearrayy)) != "<type 'bytearray'>":	
		print('[!] to_bytes is not bytearray')
		return 0
	
	if endianness=='little':
		bytearrayy.reverse()

	size=len(bytearrayy)
		
	ret=0
	it=0
	while bytearrayy:
		ret|=bytearrayy.pop()<<(8*(size-it-1))
		it+=1
	
	return ret



class stk_entry():

	def __init__(self,issymb,value):
		self.issymb=issymb
		self.value=value

	def __repr__(self):
		
		if self.issymb: 
			print('%s is symbolic'%self.value)
			return self.value
		else:
			return str(self.value)


	def __hex__(self): 
		if self.issymb:
			return self.value
		else:
			return hex(self.value)


	def display(self): 
		if self.issymb:
			return '[SYMB] %s'%self.value
		else:
			return '[NON SYMB] %s'%hex(self.value)



	def issymbb(self):
		return self.issymb


class stack:

	def __init__(self):
		self.stack = [] 

	def __len__(self):
		return len(self.stack)

	def __repr__(self):
		self.__str__()

	def __str__(self):
		stkcpy = self.stack
		i=0
		strret=[] 
		strret.append('----------------') 
		strret.append('len:'+str(len(stkcpy)))
		for x in stkcpy:
			if x.issymb:
				strret.append('[%d] [SYMB] %s'%(i,x.value))
			else: 
				strret.append('[%d] %s'%(i,hex(x.value)))
			i+=1	
		strret.append('----------------') 
		return '\n'.join(strret) 

	#DO NOT USE IT 
	#BUT IF SO NEED A STK_ENTRY 
	def append(self,value):
		self.stack.append(value)
		

	def decode_itype(self,icode):
		pass

	

	def addr(self,v):
		print('addr')
		self.stack.append(stk_entry(False,v))

	def rot(self):
		print('rot')
		f=self.stack.pop()
		m=self.stack.pop()
		l=self.stack.pop()
	
		self.stack.append(m)
		self.stack.append(f)
		self.stack.append(l)
							
	def swap(self): 
		print('swap')
		f=self.stack.pop()
		l=self.stack.pop()

		self.stack.append(f)
		self.stack.append(l)

	#Will be used for all encoding, the value must be already computed 
	def lit(self,v):
		print('lit')
		self.stack.append(stk_entry(False,v))
	
	def andd(self):
		print('andd')
		f=self.stack.pop()
		m=self.stack.pop()
		if f.issymbb() == True or m.issymbb() == True:
			self.stack.append(stk_entry(True,'(%s & %s)'%(str(f.value),str(m.value))))
		else:
			self.stack.append(stk_entry(False,f.value&m.value))

	def shr(self):
		print('shr') 
		f=self.stack.pop()
		if f.issymb:
			self.stack.append(stk_entry(True,'(%s >> 1)'%f.value))
		else: 	
			self.stack.append(stk_entry(False,f.value>>1))

	def shl(self):
		print('shl')
		f=self.stack.pop()
		if f.issymb:
			self.stack.append(stk_entry(True,'(%s << 1)'%f.value))
		else:
			self.stack.append(stk_entry(False,f.value<<1))
	
	def shra(self):
		print('shra') 
		f=self.stack.pop()
		l=self.stack.pop()
		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s << %s)'%(l.value,f.value)))
		else:
			self.stack.append(stk_entry(False,l.value<<f.value))
		
	
	def dup(self):
		print('dup') 
		l=self.stack.pop()
		self.stack.append(l)
		self.stack.append(l)

	def pick(self,it):
		print('pick')
		self.stack.append(self.stack[len(self.stack)-it-1])

	
	def minus(self):
		print('minus') 
		f=self.stack.pop()
		l=self.stack.pop()
		if f.issymb or l.issymb:
				self.stack.append(stk_entry(True,'(%s - %s)'%(str(l.value),str(f.value))))
		else:
			self.stack.append(stk_entry(False,l.value-f.value))

	def plus(self):
		print('plus') 
		f=self.stack.pop()
		l=self.stack.pop()
	
		if f.issymb or l.issymb:

			self.stack.append(stk_entry(True,'(%s + %s)'%(str(l.value),str(f.value))))
		else:
			self.stack.append(stk_entry(False,(l.value+f.value)))


	def deref_size(self,size):
		print('deref_size : %d'%size)
		global MEM_40024C
		f=self.stack.pop()
		if f.issymb:
			s=stk_entry(True,'MEM_40024C[%s]'%f.value)
		else: 
		
			if f.value >=0x40024C:
				idx = f.value-0x40024C
				#wrapper for from byte
				i = tto_bytes(MEM_40024C[idx:idx+4],'little')
				
				s=stk_entry(False,i)
				
			else : 
				print('attenting to access %s'%hex(f))	
				s=stk_entry(True,'MEM_%s'%hex(f))

		self.stack.append(s)
	#	self.stack.append(blob[f-base_shit:f-base_shit+4])

	
		
	def xor(self):
		print('xor') 
		f=self.stack.pop()
		l=self.stack.pop()
		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s ^ %s)'%(f.value,l.value)))
		else:
			self.stack.append(stk_entry(False,f.value^l.value))
		
	def orr(self):
		print('orr')
		f=self.stack.pop()
		l=self.stack.pop()
		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s or %s)'%(f.value,l.value)))
		else:
			self.stack.append(stk_entry(False,f.value|l.value))


	def drop(self):
		print('drop') 
		self.stack.pop()

	def regn(self):
		print('regn') 
		print('[!]Unwind_GetGP')

	def div(self):
		print('div')
		
		f=self.stack.pop()
		l=self.stack.pop()

		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s // %s)'%(f.value,l.value)))
		else:
			try:
				self.stack.append(stk_entry(False,l.value//f.value))
			except Exception as e:
				print('[!]Error div instruction: %s'%e.__str__())
		
	def mul(self): 
		print('mul') 
		f=self.stack.pop()
		l=self.stack.pop()

		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s * %s)'%(f.value,l.value)))
		else:
			self.stack.append(stk_entry(False,f.value*l.value))

	def over(self):
		print('over') 
		f=self.stack.pop()
		l=self.stack.pop()


		self.stack.append(l)
		self.stack.append(f)


	def mod(self):
		print('mod') 
		f=self.stack.pop()	
		l=self.stack.pop()

		if f.issymb or m.issymb:
			self.stack.append(stk_entry(True,'(%s mod %s)'%(f.value,l.value)))
		else:
			try:	
				pe = f//l
				self.stack.append(stk_entry(False,l-pe*f))
			except Exception as e: 
				print('[!] Error mod instruction: %s'%e.__str__())
		
	def nott(self):
		print('not')
		f=self.stack.pop()
		if f.issymb:		
			self.stack.append(stk_entry(True,'(not %s)'%f.value))
		else:
			self.stack.append(stk_entry(False,~f))

	
	def neg(self):
		print('neg')
		f=self.stack.pop()
		if f.issymb:		
			self.stack.append(stk_entry(True,'(neg %s)'%f.value))
		else:

			self.stack.append(stk_entry(False,-f.value))

	#Attention: v value must be sleb128 decoded before
	def plus_const(self,v):
		print('plus_const')
		f=self.stack.pop()
		if f.issymb:		
			self.stack.append(stk_entry(True,'(%s + %s)'%(f.value,str(v))))
		else:
			self.stack.append(stk_entry(False,f.value+v))

	def eq(self,v):
		print('eq')
		f=self.stack.pop()
		l=self.stack.pop()
		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s == %s)'%(f.value,l.value)))
		else:
			self.stack.append(stk_entry(False,(1 if f==l else 0)))
 
	def ne(self,v):
		print('ne')
		f=self.stack.pop()
		l=self.stack.pop()
		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s != %s)'%(f.value,l.value)))
		else:
			self.stack.append(stk_entry(False,(1 if f!=l else 0)))
		


	def ge(self,v):
		print('ge')
		f=self.stack.pop()
		l=self.stack.pop()

		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s >= %s)'%(f.value,l.value)))
		else:
			self.stack.append(stk_entry(False,(1 if f>=l else 0)))
	
	

	def gt(self,v):
		print('gt')
		f=self.stack.pop()
		l=self.stack.pop()
		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s > %s)'%(f.value,l.value)))
		else:
			self.stack.append(stk_entry(False,(1 if f>l else 0)))

	
		
	def le(self,v):
		print('le')
		f=self.stack.pop()
		l=self.stack.pop()

		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s <= %s)'%(f.value,l.value)))
		else:
			self.stack.append(stk_entry(False,(1 if f<=l else 0)))
	

	def lt(self,v):
		print('lt')
	
		f=self.stack.pop()
		l=self.stack.pop()

		if f.issymb or l.issymb:
			self.stack.append(stk_entry(True,'(%s < %s)'%(f.value,l.value)))
		else:
			self.stack.append(stk_entry(False,(1 if f<l else 0)))


	def regn(self,v):
		uleb128 =(0x80 | (v&(0x7F<<7)) << 7) |  v & 0x7F
		self.stack.append(stk_entry(False,uleb128)) 

	def breg(self,n,v):
		print('breg') 
		print('[!] not implemented')
		#get value in register n, and add signed uleb128 value v 
		#TODO not supported
		pass 	

	def fbreg(self,v):
		print('fbregs')
		print('[!] not implemented')
		#not supported 
		pass
	
	def bregx(self,reg,offset):
		print('bregx')
		print('[!] not implemented')
		#not supported
		pass

			


def execute(insn):


	global stk


	print('decoding %s'%hex(insn.itype))

	if insn.itype == 0: # addr
		stk.addr(insn.Op1.value)
	elif insn.itype == 1: #deref
		stk.deref_size(8) # 8 because aarch64
	elif insn.itype in range(2,11): 
		stk.lit(insn.Op1.value)
	elif insn.itype == 12: 
		stk.dup()
	elif insn.itype == 13:	
		stk.drop()
	elif insn.itype == 14: 
		stk.over()
	elif insn.itype == 15:
		stk.pick(insn.Op1.value)
	elif insn.itype == 16:
		stk.swap()
	elif insn.itype == 17: 
		stk.rot()
	elif insn.itype == 18:
		print('[!] xderef not implemented')

	elif insn.itype == 19:
		stk.abs()


	elif insn.itype == 20:
		stk.andd()

	elif insn.itype == 21:
		stk.div()

	elif insn.itype == 22:
		stk.minus()

	elif insn.itype == 23:
		stk.mod()
	elif insn.itype == 24:
		stk.mul()

	elif insn.itype == 25:
		stk.neg()
	elif insn.itype == 26:
		stk.nott()
	elif insn.itype == 27:	
		stk.orr()
	elif insn.itype == 28:
		stk.plus()
	elif insn.itype == 29:
		stk.plus_const(insn.Op1.value)
	elif insn.itype == 30:
		stk.shl()

	elif insn.itype == 31:
		stk.shr()
	elif insn.itype == 32:
		stk.shra()
	elif insn.itype == 33:
		stk.xor()

	elif insn.itype == 34:
		print('[*] Skip not implemented') #TODO
	elif insn.itype == 35: 
		print('[*] Branch not implemented') #TODO
	elif insn.itype == 36:
		stk.eq()
	elif insn.itype == 37:
		stk.ge()
	elif insn.itype == 38:
		stk.gt()

	elif insn.itype == 39:
		stk.le()

	elif insn.itype == 40:
		stk.lt()
	elif insn.itype == 41:
		stk.ne()

	elif insn.itype== 42:
		stk.lit(insn.Op1.reg)
	elif insn.itype == 43:
		stk.regn(int(insn.Op1.reg)) 
	elif insn.itype == 44:
		print('[!] breg not supported!')

	elif insn.itype == 45:
	
		print('[!] regx not supported!')
	elif insn.itype == 46:

		print('[!] fbreg not supported!')

	elif insn.itype == 47:
		print('[!] bregx not supported!')

	elif insn.itype == 48:
		print('[!] Piece not supported')

	elif insn.itype == 49:
		stk.deref_size(insn.Op1.value)
	
	elif insn.itype == 50:
		print('[!] xderef_size not supported')
	
	elif insn.itype == 51 :
		pass
		
	elif insn.itype == 0xe0 or insn.itype == 0xFF:
		print('[!] lo/hi{user} not supported!') 




def ascii_to_bytearray(str):
	

	ba = []
	for s in str:
		ba.append(hex(ord(s)).replace('0x',''))

	return int(''.join(ba),16)
		







def doit(cur_ea):
	global stk
	#fetch
	
	#decode
	insn = ida_ua.insn_t()
	lenn = ida_ua.decode_insn(insn,cur_ea) 
	#execute
	execute(insn)	
	print(stk)
	return find_code(cur_ea,SEARCH_DOWN)



def init():

	global stk

	stk = stack() 
	stk.append(stk_entry(True,'symb0to8'))
#	print(stk)
	stk.append(stk_entry(True,'symb8to1'))
#	print(stk)
	stk.append(stk_entry(True,'symb1to2'))
#	print(stk)
	stk.append(stk_entry(True,'symb2to3'))
#	print(stk)
	stk.append(stk_entry(True,'symb8to1'))
#	print(stk)
	stk.append(stk_entry(False,0))
#	print(stk)
	stk.append(stk_entry(True,'symb0to8'))
#	print(stk)
	stk.append(stk_entry(False,0))
#	print(stk)
	stk.append(stk_entry(True,'symb1to2'))
#	print(stk)
	stk.append(stk_entry(True,'symb2to3'))
#	print(stk)


if __name__ == '__main__':
	
	global MEM_40024C
	
	with open('40024C.bin','rb') as fout:
		MEM_40024C = bytearray(fout.read())

	


	init()
	
	global stk

	start_ea = 0x40030C - 1 
	end_ea 	 = 0x40039C 


	fout = open('/tmp/random.txt','w+') 

	while(start_ea < end_ea):
		print(hex(start_ea))
		print('stack len : %d'%len(stk))
		start_ea = doit(start_ea)
		fout.write('%s\n%s\n'%(hex(start_ea),str(stk)))

	
