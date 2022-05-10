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
        self.lfsr.info()
    def run(self, count):
        for n in range (count):
            self.lfsr.next()
        return swap32binarr(self.lfsr.state)
    
    def word(self):
        return self.run (32)

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
        
        # Reverse key to match LFSR
        key = key[::-1]

        # Note feedback is backwards and bit10 is corrected
        # compared to online images
        poly=[48, 43, 39, 38, 36, 34, 33, 31, 29, 24, 23,
              21, 19, 13, 9, 7, 6, 5]
        # Main crypto1 state
        self.sr = LFSR (initstate=key,fpoly=poly)

    def Output(self, bits, xor_in=[]):

        # 3 NLFs in two layers
        nla = NLF(0x9e98)
        nlb = NLF(0xb48e)
        nlc = NLF(0xec57e80a)
        out = []
        for n in range (bits):
            s = self.sr.state
            
            # Cycle LFSR with feedback
            self.sr.next()

            # XOR input if necessary
            if n < len(xor_in):
                self.sr.state[0] ^= xor_in[n]
                
            # Calculate layer one
            layer1 = [nla.compute ([s[0], s[2], s[4], s[6]]),
                      nlb.compute ([s[8], s[10], s[12], s[14]]),
                      nla.compute ([s[16], s[18], s[20], s[22]]),
                      nla.compute ([s[24], s[26], s[28], s[30]]),
                      nlb.compute ([s[32], s[34], s[36], s[38]])]

            # Get output from NLF layers
            b = nlc.compute (layer1)
            out.append (b)

        # Return output
        return out
        
# UID
uid = int('0x6ad2f78d', 16)
nt = int ('0x01200145', 16)
nr = int ('0x3a90b2f2', 16)

# XOR them
uid_nt = uid ^ nt

cipher = Crypto1('0xFFFFFFFFFFFF')
cipher.Output (32, int2binarr(uid, 32)[::-1])

a = cipher.Output (8, int2binarr (0x3a, 8)[::-1])
b = cipher.Output (8, int2binarr (0x90, 8)[::-1])
c = cipher.Output (8, int2binarr (0xb2, 8)[::-1])
d = cipher.Output (8, int2binarr (0xf2, 8)[::-1])
dump_binarr (a)
dump_binarr (b)
dump_binarr (c)
dump_binarr (d)

prng = PRNG ('0x1234')
#dump_binarr(prng.word ())
lfsr = LFSR (initstate='random',
             fpoly=[16,14,13,11], counter_start_zero=False)
lfsr.info()

fig, ax = plt.subplots(figsize=(8,3))
for _ in range(35):
  ax.clear()
  lfsr.Viz(ax=ax, title='R1')
  plt.ylim([-0.1,None])
  #plt.tight_layout()
  lfsr.next()
  fig.canvas.draw()
  plt.pause(0.1)
