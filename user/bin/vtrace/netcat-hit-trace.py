# testTask.py
#
# for public release, 2012
#
# Brandon Edwards


import os
import sys
import socket
import struct
import binascii
import time
import pickle
import toolbagcomm
from multiprocessing import Process

sys.path.append(os.getcwd()+os.sep+"dbg")


class RemoteTask:
    def __init__(self, fname, agentdata, serverdata):
        self.fname = fname
        self.agentdata = agentdata
        self.serverdata = serverdata

        self.ip = agentdata[0]
        self.port = agentdata[1]
        self.key = agentdata[2]

        self.serverip = serverdata[0]
        self.serverport = serverdata[1]
        self.serverkey = serverdata[2]

        self.arguments = None
        #self.agentdata = agentdata
        #ToolbagTask.ToolbagTask.__init__(self, agentdata, serverdata)

    def setArguments(self, arguments):
        self.arguments = arguments
        print "[*] Arguments are", self.arguments

    def runProcess(self, targetfunc, arguments):
        print "[*] args:", arguments

        runproc = Process(target=targetfunc, args=arguments)
        runproc.start()
        #llofthethings["trace_process"]=runproc
    
    def executeTrace(self, cmdline, startVA):
        import vtrace
        import vdb.stalker as stalker
        print "[*] executeTrace: %s %s" % (cmdline, startVA)
        self.trace = vtrace.getTrace()
        self.trace.execute(cmdline)
        self.trace.setMode("RunForever", True)
#        stalker.addStalkerEntry(self.trace, 0x00403047)
        stalker.addStalkerEntry(self.trace, int(startVA, 16))

        while self.trace.isAttached():
            self.trace.run()

        hits = stalker.getStalkerHits(self.trace)

        for hit in hits:
            print "[*] hit: %08x" % hit

        data = pickle.dumps(hits)
        self.sendResults(data)

    def sendResults(self, results):
        queue = toolbagcomm.QueueClient(self.serverip, self.serverport, self.serverkey)
        header = (self.ip, self.port, self.key, "agentresults", "trackrecv", None)
        packet = (header, results)
        queue.send(packet)

    # override run() to do something
    def run(self):
       self.runProcess(self.executeTrace, self.arguments) 


class ToolbagTask:
    def __init__(self, fname, agentdata, serverdata):
        self.fname = fname
        self.agentdata = agentdata
        self.serverdata = serverdata

        self.ip = agentdata[0]
        self.port = agentdata[1]
        self.key = agentdata[2]

        self.serverip = serverdata[0]
        self.serverport = serverdata[1]
        self.serverkey = serverdata[2]

        self.arguments = None
        #self.agentdata = agentdata
        #ToolbagTask.ToolbagTask.__init__(self, agentdata, serverdata)

    def setArguments(self, arguments):
        self.arguments = arguments
        print "[*] Arguments are", self.arguments

    def process(self, ui_obj):
        hits = ui_obj.global_hook.retvals["trackrecv"]
        print "[*] size of hits is: %i" % len(hits)
        for hit in hits:
            print "[*] Hit Address: 0x%x" % hit
            
        ui_obj.highlightAddressList(hits)

    def run(self, ui_obj):
        agent=ui_obj.myhost.agent
        # send file to agent
        # get file data 

        fd = open(ui_obj.options['vtrace_scripts_dir'] + os.sep + self.fname, "rb")
        fdata = fd.read()
        fd.close()
        print "[*] Sending script to Agent"
        agent.connect()
        agent.writeFile(self.fname, fdata)

        # load module remotely
        print "[*] Remotely loading module"
        modulename = self.fname.split(".py")[0]
        agent.loadmodule(modulename)

        print "[*] Instantiating remote task"
        agentmodule = agent.__getattr__(modulename)
        agent.remoteTask = agentmodule.RemoteTask(self.fname, agent.agentData, ui_obj.myhost.serverData)
        agent.remoteTask.setArguments(agent.toolbagTask.arguments)

        print "[*] Running task on Agent"
        agent.remoteTask.run()
    
    def prep(self, ui_obj):
        # test QtGui
        from PySide import QtCore, QtGui

        class PrepDialog(QtGui.QDialog):
            def __init__(self, ui_obj, fname, parent=None):
                super(PrepDialog, self).__init__(parent)

                self.fname = fname
                self.ui_obj = ui_obj
                self.field1 = QtGui.QInputDialog()
                self.field2 = QtGui.QInputDialog()
                self.field1.setOption(QtGui.QInputDialog.NoButtons)
                self.field2.setOption(QtGui.QInputDialog.NoButtons)
                self.field1.setLabelText("Command Line:")
                self.field2.setLabelText("Start Address:")
                self.field1.setTextValue("")
                self.field2.setTextValue(hex(ui_obj.provider.currentEA()))

                self.field1.keyPressEvent = self.keyPressEvent
                self.field2.keyPressEvent = self.keyPressEvent
                
                confirm = QtGui.QPushButton("Prepare")
                confirm.clicked.connect(self.prepareTask)

                layout = QtGui.QVBoxLayout()
                layout.addWidget(self.field2)
                layout.addWidget(self.field1)
                
                layout.addWidget(confirm)
                
                self.setLayout(layout)
                self.setWindowTitle("Prepare Script")
                self.setWindowModality(QtCore.Qt.ApplicationModal)
                self.show()

            def prepareTask(self):
                self.command = self.field1.textValue()
                self.startVA = self.field2.textValue()
                print "[*] using args: %s & %s" % (self.command, self.startVA)
                agent = self.ui_obj.myhost.agent
                agent.toolbagTask.setArguments((self.command, self.startVA))

                self.done(1)
                self.hide()

        prepinfo = PrepDialog(ui_obj, self.fname)

