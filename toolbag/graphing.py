# graphing.py
#
# for public release, 2012
#
# Aaron Portnoy
# Peter Vreugdenhil


# IDA
from idc import *
from idaapi import *
from idautils import *

# removed from public release
# networkx
#import networkx as nx

#
import database


# deprecated in favor of Peter's BlockPathGraph
class BBPathFinder(object):
    def __init__(self, start, end, options):
        self.start = start
        self.end = end
        self.options = options


    def get_blocks(self):
        func = idaapi.get_func(self.start)
        b = database.blocks(func.startEA, func.endEA)
        res = set()
        for item in b:
            res.add(item[0])
        
        return list(res)


    def gen_dict(self):
        a = self.get_blocks()

        addrs = set()
        graphygraph = {}
        
        for head in a:

            instr = head
            while True:

                if instr == idaapi.BADADDR:
                    #print "Hit BADADDR, breaking"
                    break

                mnem = GetMnem(instr) 
          
                if mnem.startswith("ret"):
                    #print "Hit return, breaking"
                    graphygraph[head] = []
                    break

                # if jump
                if mnem.startswith("j"):

                    # now we need to get the code references
                    coderefs = list(set(CodeRefsFrom(instr, 1)))

                    if graphygraph.has_key(head):
                        graphygraph[head].extend(coderefs)
                    else:
                        graphygraph[head] = coderefs

                    # break out, get the next basic block head
                    break

                else:
                    instr = idc.NextHead(instr, idaapi.get_func(instr).endEA)

        return graphygraph


    def plot_path(self):
        graph_dict = self.gen_dict()

        G = nx.DiGraph()

        for k, values in graph_dict.iteritems():
            G.add_node(k)
            for v in values:
                G.add_node(v)
                G.add_edge(k,v)

        path = nx.shortest_path(G, self.start, self.end)

        if self.options['path_coloring_enabled']:
            print 'enabled coloring'
            for addy in path:
                idc.SetColor(addy, idc.CIC_ITEM, self.options['bb_path_color'])

        return path
        