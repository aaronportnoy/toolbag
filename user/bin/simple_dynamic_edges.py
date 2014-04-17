# simple_dynamic_edges.py
#
# for public release, 2012
#
# Aaron Portnoy




from idautils import XrefsFrom
from idaapi import fl_CN as call_near, fl_CF as call_far

from PySide import QtGui, QtCore
from providers import ida

provider = ida.IDA()

def init():
    DynamicCallDiag(ui_obj)
	

class DynamicCallDiag(QtGui.QDialog):
    def __init__(self, ui_obj, parent=None):
        super(DynamicCallDiag, self).__init__(parent)

        self.ui_obj = ui_obj
        self.field1 = QtGui.QInputDialog()
        #self.field2 = QtGui.QInputDialog()
        self.field1.setOption(QtGui.QInputDialog.NoButtons)
        #self.field2.setOption(QtGui.QInputDialog.NoButtons)
        self.field1.setLabelText("Properties of destination initialization:")
        #self.field2.setLabelText("Optional Group:")

        self.field1.keyPressEvent = self.keyPressEvent
        #self.field2.keyPressEvent = self.keyPressEvent
        
        confirm = QtGui.QPushButton("Go")
        confirm.clicked.connect(self.add_dyn_edges)

        layout = QtGui.QVBoxLayout()
        #layout.addWidget(self.field2)
        layout.addWidget(self.field1)
        
        layout.addWidget(confirm)
        
        self.setLayout(layout)
        self.setWindowTitle("Dynamic Edges")
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.show()


    def add_dyn_edges(self):
       
        properties = filter(lambda x: len(x) > 0 and x or None, self.field1.textValue().strip(",").encode('UTF-8').split(" "))

        currentEA = provider.currentEA()
        startEA   = provider.funcStart(currentEA)
        endEA     = provider.funcEnd(currentEA)
        
        all_addresses = list(provider.iterInstructions(startEA, endEA))
        all_addresses.extend(provider.iterFuncChunks(startEA))
        all_addresses = list(set(all_addresses))

        res = {}
        for head in all_addresses:
            disasm = filter(lambda z: z != None and z, map(lambda y: len(y) > 0 and y.strip(",") or None, provider.getDisasm(head).split(" ")))

            success = True
            for i in xrange(0, len(properties)):
                token = properties[i]

                if len(token) > 0:
                    if token != disasm[i]:
                        success = False
                        break


            if success:
            	sub_xref = None
            	xrefs = list(XrefsFrom(head))
            	for x in xrefs:
            		if x.type == 1:
            			sub_xref = x.to
            			break
                if len(xrefs) > 0 and sub_xref != None:
                    res[head] = sub_xref

        for address, dest in res.iteritems():
            try:
                provider.makeFunc(dest)
            except Exception as detail:
                if self.ui_obj.options['architecture'] == '32':
                    print "[!] Unable to MakeFunction at 0x%08x" % dest
                elif self.ui_obj.options['architecture'] == '64':
                    print "[!] Unable to MakeFunction at 0x%016x" % dest
                break

            if self.ui_obj.options['architecture'] == '32':
                print "[*] Found: 0x%08x %s with a cross-reference to 0x%08x" % (address, provider.getDisasm(address), dest)
            elif self.ui_obj.options['architecture'] == '64':
                print "[*] Found: 0x%08x %s with a cross-reference to 0x%016x" % (address, provider.getDisasm(address), dest)

            self.ui_obj.addEdgeSource(userEA=currentEA)
            self.ui_obj.addEdgeDest(userEA=dest)
        
        self.done(1)
        self.hide()

        return res
