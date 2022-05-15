#!/bin/env python3
#
# Mifare cipher1 implementation in python
#

import numpy as np
import matplotlib.pyplot as plt
from pylfsr import LFSR
import struct

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

        # Only 16 bits used to seed the PRNG
        init = [0] * 16 + init[16:32]

        # Swap bytes
        init = swap32binarr (init)
        self.lfsr = LFSR (initstate=init,
                          fpoly=[16,14,13,11])
        #self.lfsr.info()
    def Run(self, count):
        for n in range (count):
            self.lfsr.next()
        return swap32int (binarr2int (self.lfsr.state))
    
    def GetWord(self):
        return self.Run (32)

    def GetByte(self):
        return self.Run (8) & 0xFF

# Crypto1 cipher
class Crypto1:
    def __init__(self, key=0, state=0):

        # Handle direct state creation
        if state != 0:
            key = state
            
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
        if state != 0:
            key = key[::-1]
        else:
            key = self.KeyDerive (key)
   
        # Note feedback is backwards and bit10 is corrected
        # compared to online images
        poly=[48, 43, 39, 38, 36, 34, 33, 31, 29, 24, 23,
              21, 19, 13, 9, 7, 6, 5]
        # Main crypto1 state
        self.sr = LFSR (initstate=key,fpoly=poly)

    def State (self):
        return self.sr.state[::-1]
    
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

    def ComputeNLF (self):
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
        return nlc.compute (layer1)
        
    def GetBit (self, inp=0, encrypt=False):

        # Compute NLF
        b = self.ComputeNLF ()
        
        # Cycle LFSR with feedback
        self.sr.next()

        # Feed in input
        self.sr.state[0] ^= inp        

        # Feedback output on encryption
        if encrypt:
            self.sr.state[0] ^= b

        # Return output
        return b

    # Shift everthing to the right
    def ShiftPrev (self):
        for n in range (47):
            self.sr.state[n] = self.sr.state[n+1]
            
    # Reverse LFSR one bit
    def ReverseBit (self, inp=0, xor_nlf=False):

        # Init b
        b = self.sr.state[0]
        
        # Get feedback bit
        for n in self.sr.fpoly[1:]:
            b ^= self.sr.state[n]
        
        # Shift back one
        self.ShiftPrev ()

        # Restore bit 47
        self.sr.state[47] = b ^ inp
        if xor_nlf:
            self.sr.state[47] ^= self.ComputeNLF()
        
    def Reverse8 (self, inp=0, xor_nlf=False):
        inp = int2binarr (inp, 8)
        for b in inp:
            self.ReverseBit (b, xor_nlf)
        
    def Reverse32 (self, inp=0, xor_nlf=False):
        self.Reverse8 (inp & 0xFF, xor_nlf)
        self.Reverse8 ((inp >> 8) & 0xFF, xor_nlf)
        self.Reverse8 ((inp >> 16) & 0xFF, xor_nlf)
        self.Reverse8 ((inp >> 24) & 0xFF, xor_nlf)
            
    def Raw (self, cnt, inp=[]):
        ret = []
        if len(inp) == 0:
            inp = [0] * cnt
        else:
            inp = inp[::-1]
        for n in range (cnt):
            ret.append (self.GetBit(inp[n]))
        return ret

    def Permute8 (self, inp=0):
        return binarr2int (self.Raw (8, int2binarr (inp, 8))[::-1])

    @staticmethod
    def RPermute8 (val):
        return binarr2int (int2binarr (val, 8)[::-1])

    @staticmethod
    def RPermute32 (val):
        ret = Crypto1.RPermute8 ((val >> 24) & 0xFF) << 24
        ret |= Crypto1.RPermute8 ((val >> 16) & 0xFF) << 16
        ret |= Crypto1.RPermute8 ((val >> 8) & 0xFF) << 8
        ret |= Crypto1.RPermute8 ((val >> 0) & 0xFF) << 0
        return ret
    
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
        print ('State before Nr: ', end='')
        dump_binarr (self.State())
        Nr = self.GetWord (nr) ^ nr
        # Generate Ar
        self.prng = PRNG (nt)
        # Cycle 32bits
        self.prng.GetWord ()
        ntp = int.from_bytes([self.prng.GetByte() for x in range (4)], 'big')
        tmp = self.GetWord()
        Ar = ntp ^ tmp
        return Nr.to_bytes (4, 'big') + Ar.to_bytes (4, 'big')

    def CardAuth (self):
        ntp = int.from_bytes([self.prng.GetByte() for x in range (4)], 'big')
        tmp = self.GetWord()
        At = ntp ^ tmp
        return At.to_bytes (4, 'big')
        
if __name__ == '__main__':

    # Init the cipher
    cipher = Crypto1(0xA0A1A2A3A4A5)
    print ('key={}'.format (hex(cipher.KeyReverse())))
    uid=0x6ad2f78d
    nt=0x01200145
    nr=0x797edb15
    print ('uid={} nt={} nr={}'.format(hex(uid), hex(nt), hex(nr)))

    # Do auth on reader
    resp1 = cipher.ReaderAuth (uid=uid, nt=nt, nr=nr)
    for b in resp1:
        print ('{} '.format(hex (b)), end='')
    print ()
    resp2 = cipher.CardAuth ()
    for b in resp2:
        print ('{} '.format(hex (b)), end='')    
    print ()

    print ('==================')
    print ('Recovering key...')
    print ('Known UID: {}'.format (hex (uid)))
    print ('Known Nt:  {}'.format (hex (nt)))
    cs1 = struct.unpack ('>I', resp1[4:])[0]
    cs2 = struct.unpack ('>I', resp2)[0]
    print ('Sniffed cs1={} cs2={}'.format (hex (cs1), hex (cs2)))
    prng = PRNG (nt)
    prng.GetWord ()
    pr1 = prng.GetWord ()
    pr2 = prng.GetWord ()
    print ('Known pr1={} pr2={} (derived from Nt)'.format (hex (pr1), hex (pr2)))
    cs1_xor_pr1 = cs1 ^ pr1
    cs2_xor_pr2 = cs2 ^ pr2
    print ('cs1^pr1={} cs2^pr2={}'.format (hex (cs1_xor_pr1), hex (cs2_xor_pr2)))
    print ('Reverse permute to get raw stream')
    ks1 = Crypto1.RPermute32(cs1_xor_pr1)
    ks2 = Crypto1.RPermute32(cs2_xor_pr2)
    print ('ks1={} ks2={}'.format (hex (ks1), hex (ks2)))
    print ('Run SAT Solver on {} {}'.format (hex(ks1),hex(ks2)))
    solution=0x2e3eb992fc85
    print ('Result sr2: {}'.format (hex(solution)))
    
    # Generate new SR with state
    print ('Generate new Cipher with known state')
    sim = Crypto1 (state=solution)

    # Reverse using cs0
    cs0 = struct.unpack ('>I', resp1[0:4])[0]
    sim.Reverse32 (cs0, xor_nlf=True)
    print ('State Nr\'=', end='')
    dump_binarr (sim.State())
    sim.Reverse32 (uid ^ nt)
    print ('Key={}'.format(hex(sim.KeyReverse())))
