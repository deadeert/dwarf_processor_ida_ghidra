####
#
#Tiny POC Dwarf emulator for IDA PRO  
#Branch instructions not implemented, but can easily be added
# 
###

import ida_ua 
import ida_idaapi
import ida_bytes
import ida_search

import tempfile

global stk
STK_ENTRY_SIZE = 8


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

  @staticmethod
  def maxsize():
    return STK_ENTRY_SIZE


class stack:

  def __init__(self,tf):
    self.stack = [] 
    self.tf = tf

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

  def append(self,value):
    self.stack.append(value)
    

  def decode_itype(self,icode):
    pass


  def addr(self,v):
    self.tf.write('addr')
    self.stack.append(stk_entry(False,v))

  def rot(self):
    self.tf.write('rot')
    f=self.stack.pop()
    m=self.stack.pop()
    l=self.stack.pop()
  
    self.stack.append(m)
    self.stack.append(f)
    self.stack.append(l)
              
  def swap(self): 
    self.tf.write('swap')
    f=self.stack.pop()
    l=self.stack.pop()

    self.stack.append(f)
    self.stack.append(l)

  def lit(self,v):
    self.tf.write('lit')
    self.stack.append(stk_entry(False,v))
  
  def andd(self):
    self.tf.write('andd')
    f=self.stack.pop()
    m=self.stack.pop()
    if f.issymbb() == True or m.issymbb() == True:
      self.stack.append(stk_entry(True,'(%s & %s)'%(str(f.value),str(m.value))))
    else:
      self.stack.append(stk_entry(False,f.value&m.value))

  def shr(self):
    self.tf.write('shr') 
    f=self.stack.pop()
    if f.issymb:
      self.stack.append(stk_entry(True,'(%s >> 1)'%f.value))
    else:   
      self.stack.append(stk_entry(False,f.value>>1))

  def shl(self):
    self.tf.write('shl')
    f=self.stack.pop()
    if f.issymb:
      self.stack.append(stk_entry(True,'(%s << 1)'%f.value))
    else:
      self.stack.append(stk_entry(False,f.value<<1))
  
  def shra(self):
    self.tf.write('shra') 
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s << %s)'%(l.value,f.value)))
    else:
      self.stack.append(stk_entry(False,l.value<<f.value))
    
  
  def dup(self):
    self.tf.write('dup') 
    l=self.stack.pop()
    self.stack.append(l)
    self.stack.append(l)

  def pick(self,it):
    self.tf.write('pick')
    self.stack.append(self.stack[len(self.stack)-it-1])

  
  def minus(self):
    self.tf.write('minus') 
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
        self.stack.append(stk_entry(True,'(%s - %s)'%(str(l.value),str(f.value))))
    else:
      self.stack.append(stk_entry(False,l.value-f.value))

  def plus(self):
    self.tf.write('plus') 
    f=self.stack.pop()
    l=self.stack.pop()
  
    if f.issymb or l.issymb:

      self.stack.append(stk_entry(True,'(%s + %s)'%(str(l.value),str(f.value))))
    else:
      self.stack.append(stk_entry(False,(l.value+f.value)))


  def deref_size(self,size):
    self.tf.write('deref_size : %d'%size)
    f=self.stack.pop()
    if f.issymb:
      s=stk_entry(True,'MEM[%s]'%f.value)
      s.stack.append(s) 
    else: 
        
      inf = ida_idaapi.get_inf_structure()
      if f.value in range(inf.min_ea,inf.max_ea): 
        val_ = ida_bytes.get_bytes(f.value,size)
        x,r = divmod(len(val_),stk_entry.maxsize())
        for i in range(0,x):
          if hasattr(int,'from_bytes'):
              s=stk_entry(False,int.from_bytes(bytearray(val_)[i:i+stk_entry.maxsize()],'little',signed=False))
          else: 
              s=stk_entry(False,struct.unpack('<Q',bytearray(val_)[i:i+stk_entry.maxsize()])[0])
          self.stack.append(s)
        if hasattr(int,'from_bytes'):
              s=stk_entry(False,int.from_bytes(bytearray(val_)[x*stk_entry.maxsize():x*stk_entry.maxsize()+r],'little',signed=False))
        else:
              if r == 1: 
                s=stk_entry(False,struct.unpack('B',bytearray(val_)[x*stk_entry.maxsize():x*stk_entry.maxsize()+r])[0])
              elif r == 2:
                s=stk_entry(False,struct.unpack('<H',bytearray(val_)[x*stk_entry.maxsize():x*stk_entry.maxsize()+r])[0])
              elif r == 4: 
                s=stk_entry(False,struct.unpack('<I',bytearray(val_)[x*stk_entry.maxsize():x*stk_entry.maxsize()+r])[0])
        self.stack.append(s)
      else :  # if memory not mapped in IDB, symbolize it. 
        self.tf.write('attenting to access %s'%hex(f))  
        s=stk_entry(True,'MEM_%s'%hex(f))
        self.stack.append(s)

  
    
  def xor(self):
    self.tf.write('xor') 
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s ^ %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,f.value^l.value))
    
  def orr(self):
    self.tf.write('orr')
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s or %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,f.value|l.value))


  def drop(self):
    self.tf.write('drop') 
    self.stack.pop()

  def regn(self):
    self.tf.write('regn') 
    self.tf.write('[!]Unwind_GetGP')

  def div(self):
    self.tf.write('div')
    
    f=self.stack.pop()
    l=self.stack.pop()

    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s // %s)'%(f.value,l.value)))
    else:
      try:
        self.stack.append(stk_entry(False,l.value//f.value))
      except Exception as e:
        self.tf.write('[!]Error div instruction: %s'%e.__str__())
    
  def mul(self): 
    self.tf.write('mul') 
    f=self.stack.pop()
    l=self.stack.pop()

    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s * %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,f.value*l.value))

  def over(self):
    self.tf.write('over') 
    f=self.stack.pop()
    l=self.stack.pop()


    self.stack.append(l)
    self.stack.append(f)


  def mod(self):
    self.tf.write('mod') 
    f=self.stack.pop()  
    l=self.stack.pop()

    if f.issymb or m.issymb:
      self.stack.append(stk_entry(True,'(%s mod %s)'%(f.value,l.value)))
    else:
      try:  
        pe = f//l
        self.stack.append(stk_entry(False,l-pe*f))
      except Exception as e: 
        self.tf.write('[!] Error mod instruction: %s'%e.__str__())
    
  def nott(self):
    self.tf.write('not')
    f=self.stack.pop()
    if f.issymb:    
      self.stack.append(stk_entry(True,'(not %s)'%f.value))
    else:
      self.stack.append(stk_entry(False,~f))

  
  def neg(self):
    self.tf.write('neg')
    f=self.stack.pop()
    if f.issymb:    
      self.stack.append(stk_entry(True,'(neg %s)'%f.value))
    else:

      self.stack.append(stk_entry(False,-f.value))

  #Attention: v value must be sleb128 decoded before
  def plus_const(self,v):
    self.tf.write('plus_const')
    f=self.stack.pop()
    if f.issymb:    
      self.stack.append(stk_entry(True,'(%s + %s)'%(f.value,str(v))))
    else:
      self.stack.append(stk_entry(False,f.value+v))

  def eq(self,v):
    self.tf.write('eq')
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s == %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f==l else 0)))
 
  def ne(self,v):
    self.tf.write('ne')
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s != %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f!=l else 0)))
    


  def ge(self,v):
    self.tf.write('ge')
    f=self.stack.pop()
    l=self.stack.pop()

    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s >= %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f>=l else 0)))
  
  

  def gt(self,v):
    self.tf.write('gt')
    f=self.stack.pop()
    l=self.stack.pop()
    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s > %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f>l else 0)))

  
    
  def le(self,v):
    self.tf.write('le')
    f=self.stack.pop()
    l=self.stack.pop()

    if f.issymb or l.issymb:
      self.stack.append(stk_entry(True,'(%s <= %s)'%(f.value,l.value)))
    else:
      self.stack.append(stk_entry(False,(1 if f<=l else 0)))
  

  def lt(self,v):
    self.tf.write('lt')
  
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
    self.tf.write('breg') 
    self.tf.write('[!] not implemented')
    pass   

  def fbreg(self,v):
    self.tf.write('fbregs')
    self.tf.write('[!] not implemented')
    #not supported 
    pass
  
  def bregx(self,reg,offset):
    self.tf.write('bregx')
    self.tf.write('[!] not implemented')
    #not supported
    pass
  
    

      


def execute(insn):


  global stk


  print('decoding %s'%hex(insn.itype))

  if insn.itype == 0: 
    stk.addr(insn.Op1.value)
  elif insn.itype == 1: 
    stk.deref_size(stk_entry.maxsize())
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



def doit(cur_ea):
  global stk
  
  #decode
  insn = ida_ua.insn_t()
  lenn = ida_ua.decode_insn(insn,cur_ea) 
  #execute
  execute(insn)  
  return ida_search.find_code(cur_ea,SEARCH_DOWN)



def init(tf):

  global stk

  stk = stack(tf) 
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


if __name__ == '__main__':

  
  start_ea = 0x40030A 
  end_ea    = 0x40039C 

  
  
  tf = tempfile.NamedTemporaryFile(mode='w+',delete=False) 
  print('[+] Logfile %s'%tf.name)

  init(tf)
  while(start_ea < end_ea):
    start_ea = doit(start_ea)
    tf.write('[0x%.8X]\n%s\n'%(start_ea,str(stk)))

  tf.close()

  
