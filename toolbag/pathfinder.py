# pathfinder.py
#
# for public release, 2012
#
# Peter Vreugdenhil
# Aaron Portnoy


# IDA
import idc
import idaapi
import idautils

#
import function


class FunctionPathFinder(object):    
    def __init__(self, master):

        self.startFunctions = set([])
        self.master = master

        
    def getParents(self, addy):
        #return self.master.xrefs_to(addy)
        return self.master.function_data[addy]['parents']

    def addStartFunction(self, addy):
        self.startFunctions.add(addy)


    def findPaths(self, addy, pathBlocks = set([]), currentPath = set([]), depth = 0, maxdepth = 9999):
        if(addy in self.startFunctions):
            pathBlocks.add(addy)
            return True
        if(depth > maxdepth):
            return False
        FoundPath = False
        for p in self.getParents(addy):
            print "parent: 0x%08x" % p
            if(p in pathBlocks):
                pathBlocks.add(addy)
                FoundPath = True
            elif(p in currentPath):
                #Check for looping
                continue
            else:
                p_found = self.findPaths(p, pathBlocks, currentPath | set([p]), depth + 1, maxdepth)
                FoundPath = FoundPath or p_found
        #print 'done looping'
        if(FoundPath):
            pathBlocks.add(addy)
        return FoundPath


class PathGraph(idaapi.GraphViewer):
    def __init__(self, funcname, affected, edges, ui_obj):
        #Lets make sure we dont open the same graph twice. (it can crash IDA ... )        
        
        
        AlreadyOpenGraph = idaapi.find_tform("call graph of 0x%08x" % funcname)
        
        if(AlreadyOpenGraph != None):
            idaapi.close_tform(AlreadyOpenGraph, 0)
            

        idaapi.GraphViewer.__init__(self, "call graph of 0x%08x" % funcname)

        self.funcname = funcname
        self.affected = affected
        self.edges = edges
        self.f_to_id = {}
        self.id_to_f = {}
        self.ui_obj = ui_obj


    def OnRefresh(self):

        self.Clear()
        self.f_to_id = {}
        self.id_to_f = {}
        for f in self.affected:
            try:
                f_id = self.AddNode(self.getText(f))
            except Exception as detail:
                print detail
            self.f_to_id[f] = f_id
            self.id_to_f[f_id] = f
        for child in self.edges:
            for parent in self.edges[child]:
                self.AddEdge(self.f_to_id[parent], self.f_to_id[child])
        return True


    def OnGetText(self, node_id):
        return self.getText(self.id_to_f[node_id])


    def OnCommand(self, cmd_id):
        """
        Triggered when a menu command is selected through the menu or its hotkey
        @return: None
        """
        if self.cmd_close == cmd_id:
            self.Close()
            return

        elif self.cmd_add_history == cmd_id:
            for func in self.f_to_id.keys():
                self.ui_obj.addToHistory(userEA=func)

            #self.ui_obj.addToHistory(add=False)




        #if self.cmd_generate == cmd_id:
        #    self.caller.generateHTML(self.blocks)
        #if self.cmd_select_all == cmd_id:
        #    self.selectAll()
        #if self.cmd_invert_selection == cmd_id:
        #    self.invertSelection()


    def Show(self):
        if not idaapi.GraphViewer.Show(self):
            return False
        self.cmd_close = self.AddCommand("Close", "F2")
        if self.cmd_close == 0:
            pass

        self.cmd_add_history = self.AddCommand("Add to History", "F4")
        if self.cmd_add_history == 0:
            print "[!] Failed to add popup menu item to basic block graph!"


            #print "Failed to add popup menu item!"
        #self.cmd_generate = self.AddCommand("Generate HTML", "F3")
        #if self.cmd_generate == 0:
        #    print "Failed to add Generate HTML menu item!"
        #self.cmd_select_all = self.AddCommand("Select All", "")
        #if self.cmd_select_all == 0:
        #    print "Failed to add Select All menu item!"
        #self.cmd_invert_selection = self.AddCommand("Invert Selection", "")
        #if self.cmd_invert_selection == 0:
        #    print "Failed to add Invert Selection menu item!"

        return True


    def OnDblClick(self, node_id):
        f_addy = self.id_to_f[node_id]
        #print "Jumping to " + hex(f_addy)
        idc.Jump(f_addy)

    
    def getText(self, addy):
        func = idaapi.get_func(addy)
        if(func):
            FName = idc.GetFunctionName(func.startEA)
            Demangled = None
            color = idc.GetColor(func.startEA, idc.CIC_ITEM)

            if color == 0xFFFFFFFF:
                color = idaapi.SCOLOR_INV
            else:
                color = idaapi.SCOLOR_STRING


            try:
                Demangled = idc.Demangle(FName,8)
            except:
                pass
            if(Demangled):
                FName = Demangled
            return idaapi.COLSTR(" " + FName + " ", color)
            return " " + FName + " "

        return " " + idc.GetDisasm(addy) + " "


###############################################################################

class BlockPathFinder(object):    

    def __init__(self):
        self.function = None
        self.startLocs = {}
        self.parents = {}
        self.blockInfo = {}
        self.loops = {}
        self.children = {}


    def analyseFunction(self, address = None):
        if(address == None):
            address = idc.ScreenEA()
        self.setFunction(address)
        if(not self.function):
            print "I have no idea what function you are talking about"
        self.fillBlockData()
        self.getAllRefs()


    def fillBlockData(self):
        func = idaapi.get_func(self.function)
        flow = idaapi.FlowChart(func)        
        for block in flow:
            self.blockInfo[block.startEA] = {'StartEA' : block.startEA, 'EndEA' : idc.PrevHead(block.endEA, block.startEA), 'OfficialEndEA' : block.endEA}        
        

    def setFunction(self, addy):
        func = idaapi.get_func(addy)
        if(not func):
            return
        self.function = func.startEA
        #for now:
        self.startLocs[self.function] = True


    def getAllRefs(self):
        start = self.function
        if(not start):
            return 
        self.fillParents(start, None, [])


    def fillParents(self, blockID, parent, walked_blocks):
        if(blockID in walked_blocks):
            #print "Found loop from %08x to %08x" % (parent, blockID)
            #We have a loop. Add Loop data + parent, and stop.
            if(not parent in self.loops):
                self.loops[parent] = set([blockID])
            else:
                self.loops[parent].add(blockID)
        else:
            if(blockID in self.parents):
                self.parents[blockID].add(parent)            
            else:
                self.parents[blockID] = set([parent])
            #loop all XRefs from ?
                childeren = self.getChildren(blockID)
                for c in childeren:
                    self.fillParents(c, blockID, walked_blocks + [blockID])   


    def getChildren(self, blockID):
        if(blockID in self.children):
            return self.children[blockID]
        else:
            children = set([])
            for x in idautils.XrefsFrom(self.blockInfo[blockID]['EndEA']):
                if(x.type == 21 or x.type == 19):
                    children.add(x.to)
                else:
                    func_x = idaapi.get_func(x.to)
                    if(func_x and func_x.startEA == self.function):
                        children.add(x.to)
            self.children[blockID] = children
        return self.children[blockID]         


    def getParents(self, addy):
        if(not addy in self.parents):
            return []
        return self.parents[addy]
    

    def findPathBlocks(self, addy, pathBlocks = set([])):
        if addy not in self.blockInfo:
            done = False
            # aaron: XXX, ghetto fix in case their current screen EA isn't at the head of a bb
            try:
                for head,vals in self.blockInfo.iteritems():
                    start_ea = vals['StartEA']
                    end_ea = vals['OfficialEndEA']
                    if addy > start_ea and addy <= end_ea:
                        addy = start_ea
                        done = True
                        break
            except Exception as detail:
                print detail

            if not done:
                print "Given BAD basic block address!"
                return False

        if(addy in self.startLocs):
            pathBlocks.add(addy)
            return True
        FoundPath = False        
        for p in self.getParents(addy):
            if(p in pathBlocks):
                pathBlocks.add(addy)
                FoundPath = True
            else:
                p_found = self.findPathBlocks(p, pathBlocks)
                FoundPath = FoundPath or p_found
        #print 'done looping'
        if(FoundPath):
            pathBlocks.add(addy)
        return FoundPath


class BlockPathGraph(idaapi.GraphViewer):
    def __init__(self, funcname, blocks, edges, blockInfo, options):
        #Lets make sure we dont open the same graph twice. (it can crash IDA ... )     
        self.options = options   
        
        AlreadyOpenGraph = idaapi.find_tform("basic block graph to " + funcname)
        if(AlreadyOpenGraph != None):
            idaapi.close_tform(AlreadyOpenGraph, 0)
        
        idaapi.GraphViewer.__init__(self, "basic block graph to " + funcname)
        self.funcname = funcname
        self.blocks = blocks
        self.blockInfo = blockInfo
        self.edges = edges
        self.block_to_id = {}
        self.id_to_block = {}


    def OnRefresh(self):
        self.Clear()
        self.block_to_id = {}
        self.id_to_block = {}
        #print 'onrefresh: self.blocks is %s' % repr(self.blocks)
        for block in self.blocks:
            try:
                b_id = self.AddNode(self.getText(block))
            except Exception as detail:
                print detail
            self.block_to_id[block] = b_id
            self.id_to_block[b_id] = block
        for parent in self.edges:
            for child in self.edges[parent]:
                self.AddEdge(self.block_to_id[parent], self.block_to_id[child])
        return True


    def OnGetText(self, node_id):
        return self.getText(self.id_to_block[node_id])


    def getBounds(self, ea):
        for head, vals in self.blockInfo.iteritems():
            start_ea = vals['StartEA']
            end_ea = vals['EndEA']
            if ea >= start_ea and ea <= end_ea:
                if ea == end_ea:
                    return (start_ea, end_ea)
                else:
                    # ghetto, but idautils.Heads skips the branch
                    proper_end = idc.NextHead(end_ea, end_ea+0x10)
                    return (start_ea, proper_end)

    def OnCommand(self, cmd_id):
        """
        Triggered when a menu command is selected through the menu or its hotkey
        @return: None
        """
        #print "command:", cmd_id
        if self.cmd_close == cmd_id:
            self.Close()
            return
        elif self.cmd_color == cmd_id:

            func_item = idaapi.get_func(idc.ScreenEA())


            # get the default color
            idc.Jump(func_item.startEA)
            idautils.ProcessUiActions("GraphDefaultColor", 0)            
            defaultcolor = idc.GetColor(func_item.startEA, idc.CIC_ITEM)

            # reset colors to default
            idc.SetColor(func_item.startEA, idc.CIC_FUNC, defaultcolor)

            # RGB
            for block in self.blocks:
                start,end = self.getBounds(block)
               # color all basic blocks
                for head in idautils.Heads(start, end):
                    idc.SetColor(head, idc.CIC_ITEM, self.options['bb_path_color'])

                #branch_insn = idc.NextHead(end, func_item.endEA)
                #print "branch instruction is at 0x%08x" % branch_insn
                #idc.SetColor(branch_insn, idc.CIC_ITEM, self.options['bb_path_color'])
            
        idaapi.refresh_idaview_anyway()
        
        #if self.cmd_generate == cmd_id:
        #    self.caller.generateHTML(self.blocks)
        #if self.cmd_select_all == cmd_id:
        #    self.selectAll()
        #if self.cmd_invert_selection == cmd_id:
        #    self.invertSelection()


    def Show(self):
        if not idaapi.GraphViewer.Show(self):
            return False
        self.cmd_close = self.AddCommand("Close", "F2")
        if self.cmd_close == 0:
            print "Failed to add popup menu to basic block graph!"


        self.cmd_color = self.AddCommand("Color", "F3")
        if self.cmd_color == 0:
            print "[!] Failed to add popup menu item to basic block graph!"
        #self.cmd_generate = self.AddCommand("Generate HTML", "F3")
        #if self.cmd_generate == 0:
        #    print "Failed to add Generate HTML menu item!"
        #self.cmd_select_all = self.AddCommand("Select All", "")
        #if self.cmd_select_all == 0:
        #    print "Failed to add Select All menu item!"
        #self.cmd_invert_selection = self.AddCommand("Invert Selection", "")
        #if self.cmd_invert_selection == 0:
        #    print "Failed to add Invert Selection menu item!"

        return True
        

    def OnDblClick(self, node_id):
        f_addy = self.id_to_block[node_id]
        #print "Jumping to " + hex(f_addy)
        idc.Jump(f_addy)

    
    def getText(self, addy):
        #print "Fetching text for %08x" % addy
        color = idaapi.SCOLOR_STRING

        if addy == function.top(addy):
            name = idc.NameEx(addy, addy)
            try:
                name = idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN))
            except:
                pass
        else:
            name = idc.NameEx(addy, addy)

        if name:
            return idaapi.COLSTR(" %s " % name, color)
        else:
            return idaapi.COLSTR(" 0x%08x " % addy, color)
            
