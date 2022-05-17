#!/bin/env python3
#
# Analyze CNF to understand relationship
# between output bits and keys
#
import re
import sys
import argparse
import graphviz
import easygraph as eg
        
class AnalyzeCNF:
    def __init__ (self, cnf_filename):

        # Read file
        cnf = []
        with open (cnf_filename, 'r') as f:
            cnf = f.readlines ()

        # Get variables and clauses
        self.vcnt, self.ccnt = [int(x) for x in cnf[0].split(' ')[2:]]
        cnf = cnf[1:]

        # Input and output leaf nodes
        self.in_leaf = []
        self.out_leaf = []
        
        # Parse name map for variables
        self.nmap = [''] * int(self.vcnt + 1)
        for line in cnf:
            if line.startswith ('c var '):
                m = re.match (r'c\svar\s(\d+)\s([a-zA-Z0-9\[\]]+)(.*)', line)
                self.nmap[int(m.group(1))] = m.group(2)

                # Add to leaf nodes if necessary
                if m.group(3) == ' (real unknown)':
                    self.out_leaf.append (int (m.group (1)))
                elif m.group (2).startswith ('output'):
                    self.in_leaf.append (int (m.group (1)))
        
        # Remove comments from lines
        cnf = [x for x in cnf if not x.startswith ('c')]

        # Convert to array of arrays
        cnf = [x.split(' ')[:-1] for x in cnf]
            
        # Remove negate and xor
        ncnf = []
        for x in cnf:
            clause = []
            for c in x:
                if c.startswith ('x'):
                    c = c[1:]
                if c.startswith ('-'):
                    c = c[1:]
                clause.append (int(c))
            ncnf.append (clause)

        # Build tree from CNF file
        self.g = eg.MultiGraph()
        self.build_graph (ncnf, cnf)

    def is_input (self, v):
        return v in self.in_leaf
    
    def is_output (self, v):
        return v in self.out_leaf

    def is_leaf (self, v):
        return self.is_input (v) or self.is_output (v)
    
    def build_graph (self, ncnf, cnf):

        # Create all nodes
        for n in range (self.vcnt):
            self.g.add_node (str (n + 1))

        # Process each clause
        for n in range (len (ncnf)):

            # Get clause and node list
            clause = cnf[n]
            nlist = ncnf[n]
            weight = len (cnf)
            attr = [{'clause':clause, 'weight':weight} for x in range (len(nlist)-1)]
            
            # Iterate over node list
            for node in nlist:

                # Get edges for node
                edges = [(node, x) for x in nlist if node != x]
                self.g.add_edges (edges, edges_attr=attr)

    def name2var (self, name):
        return self.nmap.index (name)
    
    # Convert CNF list of vars to name
    def var2name (self, l=[]):
        ret = []
        for n in l:
            m = re.match (r'([x-]*)(\d+)', n)
            ret.append (m.group(1) + self.nmap[int(m.group(2))])
        return ret

    def list2name (self, l=[]):
        return [self.nmap[x] for x in l]
            
    def clause2str (self, l=[]):
        _ = ''
        if l[0][0] == 'x':
            xor_clause = True
            l[0] = l[0][1:]
        else:
            xor_clause = False
        for v in l:
            if xor_clause:
              _ += str(v) + ' ^ '
            else:
              _ += str(v) + ' | '
        return _[:-2] + '= 1'
            
    def test_node (self, a):
        if isinstance (a, str):
            a = self.name2var (a)
        clist = []
        nlist = []
        for n in self.g.neighbors (a):
            if self.g[a][n]['clause'] not in clist:
                clist.append (self.g[a][n]['clause'])
            nlist.append (n)
        print ('neighbor({}):{}'.format (self.nmap[a], self.list2name (nlist)))
        for c in clist:
            print (self.clause2str(self.var2name (c)))
            
if __name__ == '__main__':
    parser = argparse.ArgumentParser ()

    parser.add_argument ('--cnf', type=str, help='CNF file')
    args = parser.parse_args ()
    
    # Do analysis
    anal = AnalyzeCNF (args.cnf)
