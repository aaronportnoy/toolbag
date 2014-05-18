"""
Switch jump viewer
original code by Aaron Portnoy / Zef Cekaj, Exodus Intelligence
Updated and modified by Jason Jones, Arbor Networks ASERT
"""
import idaapi
from idaapi import *
from idc import *
from idautils import *
from PySide import QtGui, QtCore


class SwitchViewer_t(PluginForm):

    #def __init__(self, data):
    #    # data should be a 3-tuple
    #    #
    #    # (address, number of cases, list of interesting calls)
    #    self.switches = data

    def Show(self):
        return PluginForm.Show(self,"Switch Jump Viewer",options = PluginForm.FORM_PERSIST)
        
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        # Get parent widget
        self.parent = self.FormToPySideWidget(form)
        self.calls = {}

        # Create tree control
        self.tree = QtGui.QTreeWidget()
        self.tree.setHeaderLabels(("Names","# Cases"))
        self.tree.setColumnWidth(0, 100)

        # Create layout
        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.tree)

        self.Create()
        self.parent.setLayout(layout)

    def OnClose(self,form):
        global SwitchForm
        del SwitchForm
        print "Closed"

    def click_tree(self):
        i = self.tree.currentItem()
        addr = i.text(0).strip()
        print addr
        if not addr.startswith("0x"):
            addr = get_name_ea(BADADDR,str(addr))
        else:
            addr = addr[2:10]
            addr= int(addr,16)
        Jump(addr)
        return

    def Create(self):
        title = "Switches"
        #root = QtGui.QTreeWidgetItem(self, title)
        comment = COLSTR("; Double-click to follow", SCOLOR_BINPREF)
        #self.AddLine(comment)
        comment = COLSTR("; Hover for preview", SCOLOR_BINPREF)
        #self.AddLine(comment)
        self.tree.clear()
        self.tree.setColumnCount(2)
        self.tree.clicked.connect(self.click_tree)
        for func in sorted(self.switches.keys()):
            func_node = QtGui.QTreeWidgetItem(self.tree)
            func_node.setText(0,func)
            func_node.setText(1,"")
            for item in self.switches[func]:
                node = QtGui.QTreeWidgetItem(func_node)
                addr = item[0]
                cases = item[1]
                address_element = "0x%08x" % addr
                node.setText(0,address_element)
                node.setText(1,"%04s" % cases)
                #line = address_element + value_element
                self.calls[addr] = item[2]
                for c in item[2]:
                    cnode = QtGui.QTreeWidgetItem(node)
                    cnode.setText(0,c[0])
                    cnode.setText(1,c[2])

            #self.AddLine(line)

        return True


    def OnDblClick(self, shift):
        line = self.GetCurrentLine()

        # skip the lines where we say "hover for preview" and so on
        if "0x" not in line: return False

        # skip COLSTR formatting bytes, find address
        start = line.find("0x")
        addr = int(line[2:line.find(":")], 16)

        Jump(addr)
        return True 

    def OnHint(self, lineno):
        # skip the lines where we say "hover for preview" and so on
        if lineno < 2: return False
        else: lineno -= 2

        line = self.GetCurrentLine()

        if "0x" not in line: return False

        # skip COLSTR formatting bytes, find address
        start = line.find("0x")
        addr = int(line[2:line.find(":")], 16)

        calls = self.calls[addr]

        res = ""
        for line in calls:
            res += COLSTR(line + "\n", SCOLOR_DREF) 

        return (1, res)

def look_for_interesting(addr):
    #interesting = ["sscanf", "sprintf", "exec", "run", "strcpy"]
    f = get_func(addr)
    interesting_calls = []
    if f is None:
        return
    for h in Heads(f.startEA,f.endEA):
        if GetMnem(h).find("call") != -1:
            interesting_calls.append("0x%08x : %s" % (h,GetDisasm(h)))
            #print "0x%08x: %s" % (h,GetDisasm(h))
            break
    return interesting_calls

def get_jlocs(sw):
    jlocs = []
    ncases = sw.ncases if sw.jcases == 0 else sw.jcases
    for i in range(ncases):
        addr = Dword(sw.jumps+i*4)
        name = get_name(BADADDR,addr)
        comm = GetCommentEx(LocByName(name),1)
        comm = comm[comm.find('case'):] if comm is not None and comm.startswith('jumptable') else comm
        jlocs.append((name,LocByName(name),comm))
    return jlocs

def get_switch_jumps(ea):
    func = get_func(ea)
    data = []
    heads=Heads(func.startEA,func.endEA)
    for head in heads:
        ic = []
        
        if (hex(Word(head)).lower() == "0x24ff" or hex(Word(head)).lower() == "24ff") and GetMnem(head).find("jmp") != -1:
            if get_switch_info_ex(head) is None: continue
            sw = get_switch_info_ex(head)
            print "[*] Switch at 0x%08x  has  %s jtable elements" % (head,sw.get_jtable_size())
            ic.extend(get_jlocs(sw))
            """
            # useful for xrefing searching, not used by me
            refs = list(CodeRefsFrom(head,0))
            for ref in refs:
                #print "--   Reference 0x%08x" % ref
                h = NextHead(ref)
                while h != BADADDR:
                    if GetMnem(h).find("call") != -1: 
                        #print "----    Call to 0x%08x" % GetOperandValue(h,0)
                        callrefs = list(CodeRefsFrom(h,0))
                        for cr in callrefs:
                            if GetFunctionFlags(cr) == -1:
                                continue
                            ic.extend(get_jlocs(
                        break
                    elif GetMnem(h).startswith("j"):
                        break
                    h = NextHead(h)
            """
            data.append((head,sw.ncases,ic))
    return data

def find_all_switch_jumps():
    global SwitchForm
    funcs = Functions()
    data = {}
    for func in Functions():
        d = get_switch_jumps(func)
        if d!= []:
            data[get_func_name(func)] = d
    SwitchForm = SwitchViewer_t()
    SwitchForm.switches = data
    SwitchForm.Show()

find_all_switch_jumps()
