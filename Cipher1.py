#!/bin/env python3
#
# Mifare cipher1 implementation in python
#

import numpy as np
import matplotlib.pyplot as plt
from pylfsr import LFSR

# Helper functions
def int2binarr (val, length):
    l = [int(x) for x in list(bin(val)[2:])]
    pad = [0] * (length - len(l))
    return pad + l

def binarr2int (arr):
    return int (''.join([str(x) for x in arr]), 2)

def dump_binarr (arr):
    print (hex (binarr2int (arr)))

def swap32int(x):
    return int.from_bytes(x.to_bytes(4, byteorder='little'),
                          byteorder='big', signed=False)
def swap32binarr (arr):
    x = binarr2int (arr)
    y = swap32int (x)
    return int2binarr (y,32)
    
# Not linear filters
class NLF:
    def __init__(self, fn):
        self.fn = fn
    def compute (self, arr=[]):
        val = binarr2int (arr)
        return 1 if ((1 << val) & self.fn) != 0 else 0

# PRNG - AKA regular LFSR
class PRNG:
    def __init__(self, init):

        # Convert possible init types
        if isinstance (init, int):
            init = int2binarr (init, 32)
        elif isinstance (init, str):
            init = int2binarr (int(init, 0), 32)
        elif isinstance (init, list):
            for x in init:
                if not isinstance(x, int) or ((x != 0) and (x != 1)):
                    raise ValueError ('Invalid init format')
        else:
            raise ValueError ('Invalid init format')

        # Swap bytes
        init = swap32binarr (init)
        self.lfsr = LFSR (initstate=init,
                          fpoly=[16,14,13,11])
        #self.lfsr.info()
    def run(self, count):
        for n in range (count):
            self.lfsr.next()
        return swap32int (binarr2int (self.lfsr.state))
    
    def GetWord(self):
        return self.run (32)

    def GetByte(self):
        return self.run (8) & 0xFF

# Crypto1 cipher
class Crypto1:
    def __init__(self, key):

        # Convert possible key types
        if isinstance (key, int):
            key = int2binarr (key, 48)
        elif isinstance (key, str):
            key = int2binarr (int(key, 0), 48)
        elif isinstance (key, list):
            for x in key:
                if not isinstance(x, int) or ((x != 0) and (x != 1)):
                    raise ValueError ('Invalid key format')
        else:
            raise ValueError ('Invalid key format')

        # Not sure where this is spec'd but matching proxmark
        key = self.KeyDerive (key)
        
        # Note feedback is backwards and bit10 is corrected
        # compared to online images
        poly=[48, 43, 39, 38, 36, 34, 33, 31, 29, 24, 23,
              21, 19, 13, 9, 7, 6, 5]
        # Main crypto1 state
        self.sr = LFSR (initstate=key,fpoly=poly)

    def KeyDerive (self, key):
        nkey = []
        for n in range (47, -1, -1):
            nkey.append (key[n ^ 7])
        return nkey

    def KeyReverse (self):
        key = self.sr.state
        nkey = 0
        idx = 47
        for b in key[::-1]:
            if (b):
                nkey |= (1 << (idx ^ 7))
            idx -= 1
        return nkey
            
    def GetBit (self, inp=0, encrypt=False):

        # 3 NLFs in two layers
        nla = NLF(0x9e98)
        nlb = NLF(0xb48e)
        nlc = NLF(0xec57e80a)
                    
        # Calculate layer one
        s = self.sr.state
        layer1 = [nla.compute ([s[0],  s[2],  s[4],  s[6]]),
                  nlb.compute ([s[8],  s[10], s[12], s[14]]),
                  nla.compute ([s[16], s[18], s[20], s[22]]),
                  nla.compute ([s[24], s[26], s[28], s[30]]),
                  nlb.compute ([s[32], s[34], s[36], s[38]])]
        
        # Get output from NLF layers
        b = nlc.compute (layer1)

        # Cycle LFSR with feedback
        self.sr.next()

        # Feed in input
        self.sr.state[0] ^= inp        

        # Feedback output on encryption
        if encrypt:
            self.sr.state[0] ^= b

        # Return output
        return b

    def Run (self, cnt):
        for n in range (cnt):
            pass
        
    def GetByte (self, inp=0, encrypt=False):
        ret = []
        inp = [x for x in int2binarr(inp, 8)[::-1]]
        for n in inp:
            ret.insert (0, self.GetBit(n, encrypt))
        return binarr2int (ret)

    def GetWord (self, inp=0, encrypt=False):
        ret = 0
        ret |= self.GetByte ((inp >> 24) & 0xFF, encrypt) << 24;
        ret |= self.GetByte ((inp >> 16) & 0xFF, encrypt) << 16;
        ret |= self.GetByte ((inp >> 8) & 0xFF, encrypt) << 8;
        ret |= self.GetByte ((inp >> 0) & 0xFF, encrypt) << 0;
        return ret

    # Gen NR AR from UID, Nt, Nr
    def ReaderAuth (self, uid, nt, nr):
        uid_nt = uid ^ nt
        self.GetWord (uid ^ nt)
        # Generate Nr
        Nr = self.GetWord (nr) ^ nr
        # Generate Ar
        self.prng = PRNG (nt)
        # Cycle 32bits
        self.prng.GetWord ()
        ntp = int.from_bytes([self.prng.GetByte() for x in range (4)], 'big')
        Ar = ntp ^ self.GetWord()
        return Nr.to_bytes (4, 'big') + Ar.to_bytes (4, 'big')

    def CardAuth (self):
        ntp = int.from_bytes([self.prng.GetByte() for x in range (4)], 'big')
        At = ntp ^ self.GetWord()
        return At.to_bytes (4, 'big')
        
if __name__ == '__main__':
    # Init the cipher
    cipher = Crypto1(0xFFFFFFFFFFFF)
    print ('key={}'.format (hex(cipher.KeyReverse())))
    uid=0x6ad2f78d
    nt=0x01200145
    nr=0x2309067a
    print ('uid={} nt={} nr={}'.format(hex(uid), hex(nt), hex(nr)))
    
    # Do auth on reader
    resp = cipher.ReaderAuth (uid=uid, nt=nt, nr=nr)
    for b in resp:
        print ('{} '.format(hex (b)), end='')
    print ()
    resp = cipher.CardAuth ()
    for b in resp:
        print ('{} '.format(hex (b)), end='')    
    print ()
