#Tiny POC Dwarf2 emulator for Ghidra plugin
#@author deadeert 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from __future__ import print_function
import array as ar
import struct

# Ghidra libs

import ghidra.program.model.mem.Memory
import ghidra.program.model.address.AddressFactory



#TODO Add User Code Here

def from_bytes(bytearrayy,endianness):
  """
  Custom from bytes method
  """
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
    self.stack.append(stk_entry(False,v))

  def rot(self):
    f=self.stack.pop()
    m=self.stack.pop()
    l=self.stack.pop()
  
    self.stack.append(m)
    self.stack.append(f)
    self.stack.append(l)
              
  def swap(self): 
    f=self.stack.pop()
    l=self.stack.pop()

    self.stack.append(f)
    self.stack.append(l)

  #Will be used for all encoding, the value must be already computed 
  def lit(self,v):
    self.stack.append(stk_entry(False,v))
  
  def andd(self):
    f=self.stack.pop()
    m=self.stack.pop()
    if f.issymbb() == True or m.issymbb() == True:
      self.stack.append(stk_entry(True,'(%s & %s)'%(str(f.value),str(m.value))))
    else:
      self.stack.append(stk_entry(False,f.value&m.value))

  def shr(self):
    f=self.stack.pop()
    if f.issymb:
      self.stack.append(stk_entry(True,'(%s >> 1)'%f.value))
    else:   
      self.stack.append(stk_entry(False,f.value>>1))

  def shl(self):
    f=self.stack.pop()
    if f.issymb:
      self.stack.append(stk_entry(True,'(%s << 1)'%f.value))
    else:
      self.stack.append(stk_entry(False,f.value<<1))
  
  def shra(self):
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s << %s)'%(l.value,f.value)))
    else:
      self.stack.append(stk_entry(False,l.value<<f.value))
    
  
  def dup(self):
    l=self.stack.pop()
    self.stack.append(l)
    self.stack.append(l)

  def pick(self,it):
    self.stack.append(self.stack[len(self.stack)-it-1])

  
  def minus(self):
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
        self.stack.append(stk_entry(True,'(%s - %s)'%(str(l.value),str(f.value))))
    else:
      self.stack.append(stk_entry(False,l.value-f.value))

  def plus(self):
    f=self.stack.pop()
    l=self.stack.pop()
  
    if f.issymb or l.issymb:

      self.stack.append(stk_entry(True,'(%s + %s)'%(str(l.value),str(f.value))))
    else:
      self.stack.append(stk_entry(False,(l.value+f.value)))


  def deref_size(self,size):
    global addr_factory
    global memory 
    addr=self.stack.pop()
    if addr.issymb:
      s=stk_entry(True,'MEM[%s]'%addr.value)
    else: 
      try:    
        target_address = addr_factory.getAddress(hex(addr)) # invokes getAddress with string hex repr. ('0xAABBCCDD') 
        jarray_8bytes = ar.array ('b', '\x00\x00\x00\x00\x00\x00\x00\x00')
        memory.getBytes ( target_address, jarray_8bytes )
        s=stk_entry(False, from_bytes(jarray_8bytes,'little'))
      except Exception as e:
        print('[!] deref_size : error generating Address struct from stk entry')
        print(e.__str__())
        s=stk_entry(True,'ERROR')
    self.stack.append(s)

  
    
  def xor(self):
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s ^ %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,f.value^l.value))
    
  def orr(self):
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s or %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,f.value|l.value))


  def drop(self):
    self.stack.pop()

  def regn(self):
    print('regn') 
    print('[!]Not supported')

  def div(self):
    
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
    f=self.stack.pop()
    l=self.stack.pop()

    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s * %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,f.value*l.value))

  def over(self):
    f=self.stack.pop()
    l=self.stack.pop()


    self.stack.append(l)
    self.stack.append(f)


  def mod(self):
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
    f=self.stack.pop()
    if f.issymb:    
      self.stack.append(stk_entry(True,'(not %s)'%f.value))
    else:
      self.stack.append(stk_entry(False,~f))

  
  def neg(self):
    f=self.stack.pop()
    if f.issymb:    
      self.stack.append(stk_entry(True,'(neg %s)'%f.value))
    else:

      self.stack.append(stk_entry(False,-f.value))

  #Attention: v value must be sleb128 decoded before
  def plus_const(self,v):
    f=self.stack.pop()
    if f.issymb:    
      self.stack.append(stk_entry(True,'(%s + %s)'%(f.value,str(v))))
    else:
      self.stack.append(stk_entry(False,f.value+v))

  def eq(self,v):
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s == %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f==l else 0)))
 
  def ne(self,v):
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s != %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f!=l else 0)))
    


  def ge(self,v):
    f=self.stack.pop()
    l=self.stack.pop()

    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s >= %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f>=l else 0)))
  
  

  def gt(self,v):
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s > %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f>l else 0)))

  
  
    
  def le(self,v):
    f=self.stack.pop()
    l=self.stack.pop()

    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s <= %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f<=l else 0)))
  

  def lt(self,v):
  
    f=self.stack.pop()
    l=self.stack.pop()

    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s < %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f<l else 0)))



  def branch(self):
    f = self.stack.pop()
    if f.issymb(): 
      print('[!] Cannot continue execution BRANCH insn met on SYMBOLIZED value')
      exit(1)  
    else:
       return f.value 
        
    


  def regn(self,v):
    self.stack.append(stk_entry(False,v)) 

  def breg(self,n,v):
    print('breg') 
    print('[!] not implemented')
    pass   

  def fbreg(self,v):
    print('fbregs')
    print('[!] not implemented')
    pass
  
  def bregx(self,reg,offset):
    print('bregx')
    print('[!] not implemented')
    pass
  
  def add_uleb(self,uleb):
    f=self.stack.pop()
    if f.issymb:
      self.stack.append(stk_entry(True,'(%s + %d')%(f.value,uleb))

      

def uleb128(value): 
  
  dec=0 
  out=0
  while (value & 0x80):
    out |= (value & 0x7F) << (dec-1) 
    value = value >> dec 
    dec+=8
  out|= (value & 0x7F) << (dec-1) 
  return out
    

def sleb128(value): 
  dec=0 
  out=0
  while (value & 0x80):
    out |= (value & 0x7F) << (dec-1) 
    value = value >> dec 
    dec+=8
  out|= (value & 0x3F) << (dec-1) 
  if value & 0x40 : return -out
  else : return out 
  
  




def init_memory():
    global memory 
    global addr_factory 
    memory = currentProgram.getMemory()
    addr_factory = currentProgram.addressFactory
    null_address = addr_factory.getAddress('0')


def init():

  global stk

  stk = stack() 
  stk.append(stk_entry(True,'symb0to8'))
  stk.append(stk_entry(True,'symb8to1'))
  stk.append(stk_entry(True,'symb1to2'))
  stk.append(stk_entry(True,'symb2to3'))
  stk.append(stk_entry(True,'symb8to1'))
  stk.append(stk_entry(False,0))
  stk.append(stk_entry(True,'symb0to8'))
  stk.append(stk_entry(False,0))
  stk.append(stk_entry(True,'symb1to2'))
  stk.append(stk_entry(True,'symb2to3'))
  print(stk)



def main() : 

  global stk


  listing = currentProgram.getListing ( ) 
  start_ea = askAddress('StartEA','StartEA:') 
  stop_ea = askAddress('StopEA','StopEA:')
  insn = listing.getInstructionAt(start_ea)

  cpt=0 
  while(insn.getAddress()!=stop_ea):
    
    mnemonic = insn.getMnemonicString() 

    if (mnemonic.strip() in ['LIT1', 'LIT1s','LIT2','LIT2s','LIT4','LIT4s','LIT8','LIT8s']): 
      ops=insn.getOpObjects(0)
      op1 = ops[0].getValue()
      print('LIT ',op1)
      stk.lit(op1)
    elif (mnemonic.strip() == 'LITu128'):
      ops=insn.getOpObjects(0)
      op1 = ops[0].getValue()
      print('LITuleb128',uleb(op1))
      stk.lit(op1) 
    elif (mnemonic.strip() == 'LITs128'):
      ops=insn.getOpObjects(0)
      op1 = ops[0].getValue()
      print('LITsleb128',sleb(op1))
      stk.lit(op1) 
    elif (mnemonic.strip() == 'DUP'):
      print('DUP') 
      stk.dup()
    elif (mnemonic.strip() == 'DROP'):
      print('DROP') 
      stk.drop()
    elif (mnemonic.strip() == 'OVER'):
      print('OVER') 
      stk.over()
    elif (mnemonic.strip() == 'PICK'):
      ops=insn.getOpObjects(0)
      op1 = ops[0].getValue()
      print('PICK ',op1) 
      stk.pick(op1) 
    elif (mnemonic.strip() == 'SWAP'):
      print('SWAP') 
      stk.swap() 
    elif (mnemonic.strip() == 'ROT'):
      print('ROT') 
      stk.rot()
    elif (mnemonic.strip() in ['XDEREF', 'DEREF']):
      print('XDEREF') 
      stk.deref_size(8)
    elif (mnemonic.strip() == 'ABS'):
      print('ABS') 
      stk.abs()
    elif (mnemonic.strip() == 'AND'):
      print('AND') 
      stk.andd()
    elif (mnemonic.strip() == 'DIV'):
      print('DIV') 
      stk.div()
    elif (mnemonic.strip() == 'MINUS'):
      print('MINUS') 
      stk.minus()
    elif (mnemonic.strip() == 'MOD'):
      print('MOD') 
      stk.mod()
    elif (mnemonic.strip() == 'MUL'):
      print('MUL') 
      stk.mod()
    elif (mnemonic.strip() == 'NEG'):
      print('NEG') 
      stk.mod()
    elif (mnemonic.strip() == 'NOT'):
      print('NOT') 
      stk.nott()
    elif (mnemonic.strip() == 'OR'):
      print('or') 
      stk.orr()
    elif (mnemonic.strip() == 'ADD'):
      print('ADD') 
      stk.plus()
    elif (mnemonic.strip() == 'ADD_ULEB'):
      ops=insn.getOpObjects(0)
      op1 = ops[0].getValue()
      print('ADD',uleb(op1))
      stk.add_uleb(uleb(op1))
    elif (mnemonic.strip() == 'SHL'):
      print('SHL') 
      stk.shl()
    elif (mnemonic.strip() == 'SHR'):
      print('SHR') 
      stk.shr()
    elif (mnemonic.strip() == 'SHRA'):
      print('SHRA') 
      stk.shr()
    elif (mnemonic.strip() == 'XOR'):
      print('XOR') 
      stk.xor()
    elif (mnemonic.strip() == 'SKIP'):
      ops=insn.getOpObjects(0)
      op1 = ops[0].getValue()
      print('SKIP ',op1)
      insn = listing.getInstructionAt(insn.getNext().getAddress()+op1)
      continue
    elif (mnemonic.strip() == 'BRA'):
      ops=insn.getOpObjects(0)
      op1 = ops[0].getValue()
      print('BRA ',op1)
      if (stk.branch()):
        insn = listing.getInstructionAt(insn.getNext().getAddress()+op1)
        continue 
    elif (mnemonic.strip() == 'EQ'):
      print('EQ') 
      stk.eq()
    elif (mnemonic.strip() == 'GE'):
      print('GE') 
      stk.ge()
    elif (mnemonic.strip() == 'GT'):
      print('GT') 
      stk.gt()
    elif (mnemonic.strip() == 'LE'):
      print('LE') 
      stk.le()
    elif (mnemonic.strip() == 'LT'):
      print('LT') 
      stk.lt()
    elif (mnemonic.strip() == 'NE'):
      print('NE') 
      stk.lt()

    elif (mnemonic.strip() in  ['REG0',
                                'REG1',
                                'REG2',
                                'REG3',
                                'REG4',
                                'REG5',
                                'REG6',
                                'REG7',
                                'REG8',
                                'REG9',
                                'REG10',
                                'REG11',
                                'REG12',
                                'REG13',
                                'REG14',
                                'REG15',
                                'REG16',
                                'REG17',
                                'REG18',
                                'REG19',
                                'REG20',
                                'REG21',
                                'REG22',
                                'REG23',
                                'REG24',
                                'REG25',
                                'REG26',
                                'REG27',
                                'REG28',
                                'REG29',
                                'REG30',
                                'REG31']):
      print('REGN') 
      stk.regn(31)
    elif (mnemonic.strip() == ['BREG0',
                               'BREG1',
                               'BREG2',
                               'BREG3',
                               'BREG4',
                               'BREG5',
                               'BREG6',
                               'BREG7',
                               'BREG8',
                               'BREG9',
                               'BREG10',
                               'BREG11',
                               'BREG12',
                               'BREG13',
                               'BREG14',
                               'BREG15',
                               'BREG16',
                               'BREG17',
                               'BREG18',
                               'BREG19',
                               'BREG20',
                               'BREG21',
                               'BREG22',
                               'BREG23',
                               'BREG24',
                               'BREG25',
                               'BREG26',
                               'BREG27',
                               'BREG28',
                               'BREG29',
                               'BREG30',
                               'BREG31',
                               'BREGX',
                               'REGX',
                               'FBREG'] ):
      print('(F)(B)REG(X) Not implemented') 
    elif (mnemonic.strip() == 'DEREFSIZE'):
      ops=insn.getOpObjects(0)
      op1 = ops[0].getValue()
      print('DEREFSIZE ',op1)
      stk.deref_size(op1) 
    elif (mnemonic.strip() == 'NOP'):
      print('NOP')
    elif (mnemonic.strip() in ['LOUSER', 'HIUSER']):
      print('(LO/HI)USER not implemented and depends on supplier implem.') 

    insn = insn.getNext()
    print(stk)
        
if __name__ == '__main__':
  init()
  init_memory()
  main()
