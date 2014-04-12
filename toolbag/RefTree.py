# RefTree.py
#
# for public release, 2012
#
# Peter Vreugdenhil
# Aaron Portnoy


import database
import analysis

from providers import ida


class RefTree(object):    

    def __init__(self, masterGraph, function_data={}):

        self.provider    = ida.IDA()
        self.masterGraph = masterGraph

        if function_data == {}:
            self.function_data = {}
        else:
            self.function_data = function_data
 

    def xrefs_to(self, addy):
        if self.masterGraph.function_data.has_key(addy):
            return self.masterGraph.function_data[addy]['parents']
        else:
            return []


    def xrefs_from(self, addy):
        if self.masterGraph.function_data.has_key(addy):
            return self.masterGraph.function_data[addy]['children']
        else:
            return []


    def del_func(self, addy):
        try:
            del(self.function_data[addy])
        except Exception as detail:
            print "[!] Failed to delete address 0x%08x from reftree." % addy
        return

    def add_func(self, addy, attrs={}):
        #get some function info
        func = self.provider.funcStart(addy)

        if attrs == {}:
            props = analysis.properties(addy)
            attrs = props.funcProps()

        addy_info = {'attr' : attrs, 'parents' : [], 'children' : []}

        if(not func):
            # probably an import
            #print "[I] Dealing with a likely import (0x%08x) in RefTree.py" % addy 
            pass
        else:
            addy = func

        for p in self.xrefs_to(addy):
            #print "xrefs_to includes 0x%08x" % p
            #Only add parent if parent already in dict
            if p in self.function_data:
                if(not p in addy_info['parents']):
                    addy_info['parents'].append(p)
                if(not addy in self.function_data[p]['children']):
                    self.function_data[p]['children'].append(addy)
            #else:
                #print "p is NOT in our self.function_data"

        for c in self.xrefs_from(addy):

            #Check to see if child is in function_data
            if c in self.function_data:
                #update child info
                if(not addy in self.function_data[c]['parents']):
                    self.function_data[c]['parents'].append(addy)

                if(not c in addy_info['children']):
                    addy_info['children'].append(c)

        if not self.function_data.has_key(addy):
            self.function_data[addy] = addy_info


    def makeTrees(self):
        #First find all root nodes:
        root_nodes = []
        for f, data in self.function_data.iteritems():
            if(len(data['parents']) == 0):
                root_nodes.append(f)
        #Make sure we end up using all available functions:
        all_funcs = set(self.function_data.keys())
        tree = []
        for r in root_nodes:
            tree.append(self.makeTree(r, set([r]), all_funcs))
        while(len(all_funcs) > 0):
            #just pop one and make a tree based on that.
            r = all_funcs.pop()
            tree.append(self.makeTree(r, set([r]), all_funcs))
        return tree

    
    def makeTree(self, addy, path = set([]), all_funcs = set([])):
        children = []
        all_funcs.discard(addy)
        if(addy in self.function_data):
            for c in self.function_data[addy]['children']:
                if(not c in path):
                    children.append(self.makeTree(c, path | set([c]),
               all_funcs))
        return (addy, children)


    def listChildren(self, tree):
        children = set([tree[0]])
        for branch in tree[1]:
            children.update(self.listChildren(branch))
        
        return children

    def addEdge(self, src, dst):
        src_func = self.provider.funcStart(src)

        if not self.function_data.has_key(dst):
            self.provider.makeFunc(dst)
            self.add_func(dst)

        parents = set(self.function_data[dst]['parents'])
        parents.add(src_func)
        self.function_data[dst]['parents'] = list(parents)

        # reftree
        try:
            children = set(self.function_data[src_func]['children'])
        except KeyError:
            self.add_func(src_func)
            children = set(self.function_data[src_func]['children'])

        children.add(dst)
        self.function_data[src_func]['children'] = list(children)

        parents = set(self.function_data[dst]['parents'])
        parents.add(src_func)
        self.function_data[dst]['parents'] = list(parents)
        




###############################################################################

class MasterRefTree(RefTree):

    def __init__(self, options):
        self.options       = options
        self.provider      = ida.IDA()
        self.function_data = {}

        self.proc = self.provider.getArch()

        self.jmp_mnem = ""

        if self.proc == "pc":
            self.call_mnem = "call"
            self.jmp_mnem = "jmp"
        elif self.proc == "arm" or self.proc == "ppc":
            self.call_mnem = "bl"
        elif self.proc == "mips":
            self.call_mnem = "jalr"

        all_funcs = database.functions()

        if self.proc == "pc":
            # XXX: hackish way to fix a crap ton of stuff...
            start = self.provider.segByBase(self.provider.segByName(".text"))
            end = self.provider.segEnd(self.provider.segByBase(self.provider.segByName(".text")))

            succeeded = 0
            for instr in self.provider.iterInstructions(start, end):
                disasm = self.provider.getDisasm(instr)
                tokens = disasm.split(" ")

                res = []
                for t in tokens:
                    if len(t) != 0:
                        res.append(t)

                prologues = [['mov', 'edi,', 'edi'], ['push', 'ebp'], ['push', 'rbp']]

                if res in prologues and instr not in all_funcs:
                    try:
                        prev_ea = self.provider.prevItem(instr, instr-0x20)
                        if prev_ea not in all_funcs:
                            if options['verbosity'] > 2:
                                print "[!] Attempting to create a function at 0x%08x" % instr
                            ret = self.provider.makeFunc(instr)
                        else:
                            continue

                        if ret:
                            if options['verbosity'] > 2:
                                print "[*] Successfully made new function at 0x%08x" % instr
                            succeeded += 1

                    except Exception as detail:
                        pass

                elif "dup(90h)" in disasm:
                    if options['verbosity'] > 2:
                        print "Found dup at 0x%08x" % instr
                    try:
                        next_ea = self.provider.nextItem(instr, instr+0x20)

                        if next_ea not in all_funcs:
                            ret = self.provider.nextItem(next_ea, 0xFFFFFFFF)
                        else:
                            continue

                        if not ret and (next_ea in database.functions()) :
                            if options['verbosity'] > 2:
                                print "[*] Successfully made new function at 0x%08x" % next_ea
                            succeeded += 1
                    except:
                        pass
               
            if succeeded != 0:
                print "[*] Successfully created %d new functions" % succeeded

        print "[*] There are %d functions to process" % len(all_funcs)

        failed = 0
        succeeded = 0

        for i in xrange(0, len(all_funcs)):

            i_actual = i+1
            ea = all_funcs[i]
            if ((i_actual % 250 == 0) or (i == len(all_funcs)-1)):
                print "[*] RefTree.py: Processing 0x%08x (%d of %d)" % (ea, i_actual, len(all_funcs))
            
            props = analysis.properties(ea)
            func_props = props.funcProps()

            try:
                self.add_func(ea, func_props)
                succeeded += 1
            except Exception as detail:
                raise
       
            except ValueError as detail:
                failed += 1
                if options['verbosity'] > 2:
                    print "0x%08x - failed to process node, %s" % (ea, detail)     
        
        print "[*] Failed to process %d functions" % failed
        print "[*] Successfully processed %d functions" % succeeded

        # now loop imports
        segs = list(self.provider.getSegments())

        if self.proc in ["arm", "ppc", "mips"]:
            idata = "extern"
        elif self.proc == "pc":
            idata = ".idata"

        for s in segs:
            if self.provider.segName(s) == idata:
                start = s
                end = self.provider.segEnd(s)

                for head in self.provider.iterData(start, end):
                    try:
                        self.add_func(head)
                    except Exception:
                        raise
                    

    def xrefs_to(self, addy):
        # we must get the xrefs to this function
        # then retrieve the EA of the top of each xref
        # return those
        res = []
        up = self.provider.cxUp(addy)
        for call_addy in up:
            func_top = self.provider.funcStart(call_addy)

            if func_top:
                res.append(func_top)

        return res


    def xrefs_from(self, addy):
        # we need to crawl the function that contains addy
        # and find every external code transfer
        # and return all the destinations
        res   = []
        start = self.provider.funcStart(addy)
        end   = self.provider.funcEnd(addy)

        if (start != None) and (end != None):

            to_process = list(self.provider.iterInstructions(start, end))
            to_process.extend(self.provider.iterFuncChunks(addy))
            
            for instr in to_process:
                # XXX gotta add support for jmps that go outside a function
                if self.call_mnem in self.provider.getMnem(instr).lower():
                    xrefs_from = self.provider.cxDown(instr)
                    res.extend(xrefs_from)
                elif self.jmp_mnem in self.provider.getMnem(instr).lower():

                    xref = self.provider.cxDown(instr)
                    if xref == []:
                        continue
                    else:
                        xref = xref[0]

                    dst_func_start = self.provider.funcStart(xref)
                    if dst_func_start != None:
                        if dst_func_start != start:
                            res.append(xref)

        res = list(set(res))
        return res


    def queryDepth(self, address, depth, direction):
        res = list()

        if direction == "down":
            # getting children
            if depth > 0:
                children = self.function_data[address]['children']

                if children == []:
                    return res

                res.extend(children)

                for child in children:
                    ret = self.queryDepth(child, depth-1, 'down')
                    if ret != []:
                        res.extend(ret)
                return res

            elif depth == 0:
                return list(set(res))
           
        elif direction == "up":
            # getting parents
            if depth > 0:
                parents = self.function_data[address]['parents']

                if parents == []:
                    return res

                res.extend(parents)

                for parent in parents:
                    ret = self.queryDepth(parent, depth-1, 'up')
                    if ret != []:
                        res.extend(ret)
                    return res
            elif depth == 0:
                return list(set(res))


    def addAttributes(self, func_top, addy, attributes):
        if not self.function_data.has_key(func_top):
            self.provider.makeFunc(func_top)
            self.add_func(func_top)

        if self.function_data[func_top]['attr'].has_key(addy):
            self.function_data[func_top]['attr'][addy].update(attributes)
        else:
            self.function_data[func_top]['attr'][addy] = attributes


    def tag(self, ea, tag, data):
        func_top = self.provider.funcStart(ea)
        if func_top == None:
            func_top = ea

        taginfo = {tag : data}

        self.addAttributes(func_top, ea, taginfo)


    def deleteTag(self, address, tag):
        for func, addy_info in self.function_data.iteritems():
            attributes = addy_info['attr']

            try:
                if tag in attributes[address]:
                    del(attributes[address][tag])
            except KeyError:
                pass


    def getAttribute(self, attr):
        res = {}
        for func, addy_info in self.function_data.iteritems():
            attributes = addy_info['attr']
            
            for k, vals in attributes.iteritems():

                # if its an address
                if isinstance(k, int) or isinstance(k, long):
                    for address_k, address_val in vals.iteritems():
                        if address_k == attr:
                            res[k] = vals
        return res

