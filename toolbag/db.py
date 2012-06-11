# db.py
#
# for public release, 2012
#
# Aaron Portnoy


# Standard Libraries
import sys
import sqlite3

from StringIO import StringIO

# Base
from store import query as q
import store

# XXX: removed from public release
#import ia32
import database
import function
import segment

# IDA provider
from providers import ida


# XXX 
# removing from the public release:
#   - emulators
#   - collectors
#   - analyzers
#   - disassembler
#
# replacing with this simple crawler
class analyze_xrefs:
    def __init__(self, options):
        self.options = options
        self.provider = ida.IDA()

    def enter(self, pc, options):
        options['database'].address(pc)['name'] = database.name(pc)
       
        xrefs_to = database.cxup(pc)    
        func_top = pc    
       
        for x in xrefs_to:
            xref_top = function.top(x)
            context = options['database'].c(xref_top) 
            context.address(x).edge((func_top, func_top)) 

        return

    def iterate(self, pc, options):
        if self.provider.segStart(pc) == 0xFFFFFFFF:
            raise ValueError('Fucking IDA')
        
        # if its a call, get the xrefs from it
        # XXX: removed ia32 from public release
        #if ia32.isCall(insn):

        proc = self.provider.getArch()

        if proc == "pc":
            call_mnem = "call"
        elif proc == "arm" or proc == "ppc":
            call_mnem = "bl"
        elif proc == "mips":
            call_mnem = "jalr"
        
        # XXX gotta add support for jmps that go outside a function
        if call_mnem in self.provider.getDisasm(pc).lower():

            xrefs_from = database.cxdown(pc)  
            func_top = function.top(pc)
            for x in xrefs_from:
                if self.provider.isCode(self.provider.getFlags(x)):
                    xref_top = function.top(x)
                    context = options['database'].c(func_top)
                    content = context.address(pc)
                    content.edge((x, x))
    
        try:
            endEA = self.provider.funcEnd(pc)
        except:
            return

        if endEA == pc:
            return
         
        # removed as we aren't in private release 
        # hlt instruction 
        #if insn[1] == "\xf4":
        #    return

        return


class collector:
    def __init__(self, analyzer, options):
        self.options = options
        self.analyzer = analyzer
        self.provider = ida.IDA()

    def go(self, ea):

        startEA = self.provider.funcStart(ea)
        endEA = self.provider.funcEnd(ea)

        if not startEA and not endEA: 
            return

        self.analyzer.enter(startEA, self.options)

        for h in self.provider.iterInstructions(startEA, endEA):
            self.analyzer.iterate(h, self.options)
    

class DB:
    """
    Main class responsible for the Toolbag DB
    """

    def __init__(self, options, create=True, existing=None):

        self.provider = ida.IDA()

        if create:
            # create the DB
            print "[*] db.py: Creating a new DB file"

            db = store.sqlite3.connect(options['full_file_name'])
            #db.isolation_level =
            self.db_obj = db

            store.driver.sqlite.Deploy(db).create()

            # mutes the pesky sqlite messages
            tmp = sys.stderr 
            sys.stderr = StringIO()
            session = store.driver.sqlite.Session(db,0)
            my_store = store.Store(session)
            sys.stderr = tmp

            all_funcs = database.functions()
            opt = {}
            opt['database'] = my_store

            self.store = my_store

            # XXX: hackish way to fix a crap ton of stuff...
            start = self.provider.segByBase(self.provider.segByName(".text"))
            end = self.provider.segEnd(self.provider.segByBase(self.provider.segByName(".text")))

            proc = self.provider.getArch()

            if proc == "pc":

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
                            print detail
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
                                succeeded +=1
                        except:
                            pass

                   
                if succeeded != 0:
                    print "[*] Successfully created %d new functions" % succeeded

            all_funcs = database.functions()
            print "[*] There are %d funtions to process" % len(all_funcs)
            failed = 0
            succeeded = 0
            for i in xrange(0, len(all_funcs)):
    
                i_actual = i+1
                ea = all_funcs[i]
                if ((i_actual % 250 == 0) or (i == len(all_funcs)-1)):
                    print "[*] db.py: Processing 0x%08x (%d of %d)" % (ea, i_actual, len(all_funcs))

                analyza = analyze_xrefs(opt)
                collecta = collector(analyza, opt)

                try:
                    collecta.go(ea)
                    succeeded += 1
                
                except ValueError as detail:
                    failed += 1
                    if options['verbosity'] > 2:
                        print "0x%08x - failed to process node, %s" % (ea, detail)
                    
                opt['database'].commit()
            
            print "[*] Failed to process %d functions" % failed
            print "[*] Successfully processed %d functions" % succeeded

            # now loop imports
            segs = list(self.provider.getSegments())

            if proc in ["arm", "ppc", "mips"]:
                idata = "extern"
            elif proc == "pc":
                idata = ".idata"

            for s in segs:
                if self.provider.segName(s) == idata:
                    start = s
                    end = self.provider.segEnd(s)

                    for head in self.provider.iterData(start, end):
                        opt['database'].address(head)['name'] = self.provider.getName(head)

                        xrefs_to = database.cxup(head)

                        for x in xrefs_to:
                            try:
                                xref_top = function.top(x)
                            except ValueError: 
                                continue
                            context = opt['database'].c(xref_top)
                            context.address(x).edge((head, head))
            self.commit()


        else:
            db = store.sqlite3.connect(options['full_file_name'])
            self.db_obj = db

            # mutes the pesky sqlite messages
            tmp = sys.stderr
            sys.stderr = StringIO()
            session = store.driver.sqlite.Session(db,0)
            sys.stderr = tmp

            my_store = store.Store(session)
            self.store = my_store
            # unpack the sqlite db to disk temporarily 
            
    
    def tag(self, address, tagname, tagvalue):
        store = self.store
        store.address(address)[tagname] = tagvalue
        self.commit()
    
    def getAttribute(self, name):
        return self.store.select(q.attribute(name))
    
    def deleteTag(self, address, tagname):
        store = self.store
        store.address(address).unset(tagname)
        self.commit()
    
    def commit(self):
        self.store.commit()
    
    def close(self):
        print "[*] Releasing lock on database"
        self.db_obj.close()
    
    def addEdge(self, src, dst):
        func_top = function.top(src)
        context = self.store.c(func_top)
        content = context.address(src)
        x = dst
        content.edge((x,x))
        self.commit()
        return True
