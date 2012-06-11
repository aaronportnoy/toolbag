# RefTree.py
#
# for public release, 2012
#
# Peter Vreugdenhil


# Standard Libraries
import sqlite3

# IDA
import idaapi
import idautils

#
from store import query as q
import store

s = None
u = None

class RefTree(object):    

    def __init__(self, db, funtion_data=None):
        global u
        global s

        if funtion_data == None:
            self.funtion_data = {}
        else:
            self.funtion_data = funtion_data

        u = db.store

 
    def xrefs_to(self, addy):
        global u

        select = q.depth(addy, -1)
        results = u.select(select)

        #print 'xrefs_to 0x%08x' % addy  
        #print results

        return results.keys()


    def xrefs_from(self, addy):
        global u
        select = q.depth(addy, 1)
        results = u.select(select)

        #print 'xrefs_from 0x%08x' % addy 
        #print results

        return results.keys()


    def del_func(self, addy):
        try:
            del(self.funtion_data[addy])
        except Exception as detail:
            print "[!] Failed to delete address 0x%08x from reftree." % addy
        return


    def add_func(self, addy):
        #get some function info
        func = idaapi.get_func(addy)

        addy_info = {'attr' : [], 'parents' : [], 'children' : []}

        if(not func):
            # probably an import
            #print "[I] Dealing with a likely import (0x%08x) in RefTree.py" % addy 
            pass
        else:
            addy = func.startEA

        for p in self.xrefs_to(addy):

            #print "xrefs_to includes 0x%08x" % p
            #Only add parent if parent already in dict
            if p in self.funtion_data:
                if(not p in addy_info['parents']):
                    addy_info['parents'].append(p)
                if(not addy in self.funtion_data[p]['children']):
                    self.funtion_data[p]['children'].append(addy)
            #else:
                #print "p is NOT in our self.funtion_data"

        for c in self.xrefs_from(addy):

            #Check to see if child is in function_data
            if c in self.funtion_data:
                #update child info
                if(not addy in self.funtion_data[c]['parents']):
                    self.funtion_data[c]['parents'].append(addy)

                if(not c in addy_info['children']):
                    addy_info['children'].append(c)

        self.funtion_data[addy] = addy_info

    def makeTrees(self):
        #First find all root nodes:
        root_nodes = []
        for f, data in self.funtion_data.iteritems():
            if(len(data['parents']) == 0):
                root_nodes.append(f)
        #Make sure we end up using all available functions:
        all_funcs = set(self.funtion_data.keys())
        tree = []
        for r in root_nodes:
            tree.append(self.makeTree(r, set([r]), all_funcs))
        while(len(all_funcs) > 0):
            #just pop one and make a tree based on that.
            r = all_funcs.pop()
            tree.append(self.makeTree(r, set([r]), all_funcs))
        return tree
    
    def makeTree(self, addy, path = set([]), all_funcs = set([])):
        childeren = []
        all_funcs.discard(addy)
        if(addy in self.funtion_data):
            for c in self.funtion_data[addy]['children']:
                if(not c in path):
                    childeren.append(self.makeTree(c, path | set([c]),
               all_funcs))
        return (addy, childeren)



    '''
    def makeTrees(self):
        #First find all root nodes:
        root_nodes = []
        for f, data in self.funtion_data.iteritems():
            if(len(data['parents']) == 0):
                root_nodes.append(f)
        if root_nodes == []:
            if self.funtion_data != {}:
                print "[!] No root node found (did you add a circular relationship with no root?)"
            return []
        tree = []
        for r in root_nodes:
            tree.append(self.makeTree(r, set([r])))
    
        return tree
    

    
    def makeTree(self, addy, path = set([])):
        childeren = []
        if(addy in self.funtion_data):
            for c in self.funtion_data[addy]['children']:
                if(not c in path):
                    childeren.append(self.makeTree(c, path | set([c])))
        return (addy, childeren)

        
    def makeTrees(self):
        #First find all root nodes:
        root_nodes = []
        for f, data in self.funtion_data.iteritems():
            if(len(data['parents']) == 0):
                root_nodes.append(f)
        tree = []
        for r in root_nodes:
            tree.append(self.makeTree(r))
    
        return tree
    

    def makeTree(self, addy):
        childeren = []
        if(addy in self.funtion_data):
            for c in self.funtion_data[addy]['children']:
                childeren.append(self.makeTree(c))

        return (addy, childeren)
    '''


    def listChildren(self, tree):
        children = set([tree[0]])
        for branch in tree[1]:
            children.update(self.listChildren(branch))
        
        return children

