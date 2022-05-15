#!/bin/env python3
#
# Simple utility that takes a CNF file
# which represents the fixed relationship
# between SR[0:47] <= Output bits
# over a given fixed time (fixed for CNF).
#
# If a corresponding output stream is given
# it will run cryptominisat to solve for
# SR[0:47] state n cycles previous

from pycryptosat import Solver
import argparse
import os
import math
import tempfile
import shutil
import subprocess
import time

# Convenience class to represent array slices and convert
# between various encodings
class CNFArray:
    def __init__(self, val, length=0):
        self._val = []

        # Handle text seed known input
        if isinstance(val, str):
            val = int (val, 0)
        if isinstance(val, int):
            # Round to nearest nibble
            cnt = length
            ncnt = math.ceil (cnt / 4) * 4
            pad = ncnt - cnt

            # If bit it set then set corresponding variable
            for n in range (ncnt-1, pad-1, -1):
                if val & (1 << n):
                    self._val.append(1)
                else:
                    self._val.append(-1)

        # Handle output from solver
        if isinstance(val, tuple):
            if isinstance (val[0], bool):
                self._val = [1 if x else -1 for x in val]


    def asList(self, offset):
        _ = []
        for x in self._val:
            _.append(offset * x)
            offset += 1
        return _

    def Reverse(self):
        self._val.reverse ()
        
    def __iter__(self):
        self.idx = 0
        return self

    def __next__(self):
        if self.idx < len (self._val):
            return self._val[self.idx]
        raise StopIteration

    def __str__(self):
        _ = ''
        for n in self._val:
            _ += str(n) + ' '
        return _

    def asBool(self):
        _ = ''
        for n in self._val:
            _ += '1' if n > 0 else '0'
        return _

    def asHex(self):
        x = 0
        for n in self._val:
            x <<= 1
            if n > 0:
                x |= 1 
        return hex(x)

class Crypto1Solver:
    def __init__(self):
        # Set on init
        self.known_offset = 0
        
        # Set local vars
        self.vrs = 0
        self.eqs = 0
        self.solver = None

    # Takes array of known bits and generates possible keys
    def Solve (self, cnf_array):
        
        # Solve equation with new assumption
        sat, solution = self.solver.solve (assumptions=cnf_array.asList(self.known_offset))
        if sat:
            key = CNFArray (solution[1:49])
            return key
        else:
            print ("Cannot solve")
            return 0
        
    # Parse the CNF into internal partial CNF without input bits
    def ParseCNF(self, cnf_filename):

        # Open file and parse
        with open (cnf_filename, 'r') as f:

            # Get header
            a, b, self.vrs, equs = f.readline ().split (' ')
            if (a != 'p') or (b != 'cnf'):
                raise ValueError ('Invalid CNF header')

            # Generate a new sat solver
            self.solver = Solver (threads=2)
            known = []
            
            # Parse each line
            for line in f.readlines():

                # Skip comment lines
                if line[0] == 'c':
                    continue

                # parse out xor clauses
                if line[0] == 'x':
                    eq = [int(x) for x in line[1:].split (' ')[:-1]]
                    if eq[0] < 0:
                        eq[0] *= -1
                        rhs = False
                    else:
                        rhs = True
                else:
                    eq = [int(x) for x in line.split (' ')[:-1]]

                # If it's a literal add to known bits
                if len (eq) == 1:
                    known.append (eq[0])
                # Add equation
                elif line[0] == 'x':
                    self.solver.add_xor_clause (eq, rhs)
                    self.eqs += 1
                else:
                    self.solver.add_clause (eq)
                    self.eqs += 1

            # Get known offset
            self.known_offset = abs (known[0])
            
            # Generate partial solution
            #start = time.time()
            #sat, solution = self.solver.solve ()
            #end = time.time()
            #print ('Solvable={} {}'.format (sat, end-start))
            
# Gen CNF problem
def GenCNF (bitlen, shift):

    seed = 'e9fc41c9746300088391274fac655039e179533ce0f43dc5582f436a8d0b6fb0'
    seedlen = int(math.ceil (bitlen / 4))
    seed = seed[0:seedlen]
    
    # Change working directory
    cdir = os.getcwd()
    os.chdir (cdir + '/grainofsalt/build')
    
    # Calculate filename and path
    # Fix name calc from output len
    filename = 'crypto1-0-' + str(bitlen) + '-' + \
               str(shift) + '-0x' + seed + '-1.cnf'
    abspath = os.getcwd() + '/satfiles/' + filename

    # Call grainofsalt
    args = ['./grainofsalt',
            '--crypto=crypto1',
            '--karnaugh=8',
            #'--xorclauses',
            '--nopropagate',
            '--outputs', str(bitlen),
            '--base-shift', str(shift)]
    proc = subprocess.Popen (args, stderr=subprocess.PIPE, stdout = subprocess.PIPE)
    proc.wait ()
    #if proc.stderr:
    #    print (proc.stderr.readlines())

    # Print generated CNF
    print ('Generated CNF: {}'.format (abspath))
        
    # Restore working directory
    os.chdir (cdir)

# Parse args
if __name__ == '__main__':
    parser = argparse.ArgumentParser ()

    # Specify arguments
    parser.add_argument ('--gen-cnf', type=int,
                        help='generate CNF given N observed bits')
    parser.add_argument ('--shift', type=int,
                         help='shift base SR before generating [0:49]')
    # Parse args
    args = parser.parse_args ()

    # Set defaults if not availble
    if not args.shift:
        args.shift = 0

    # Call generator
    if args.gen_cnf:
        GenCNF (args.gen_cnf, args.shift)
