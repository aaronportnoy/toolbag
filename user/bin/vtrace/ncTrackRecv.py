# ncTrackRecv.py
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

sys.path.append("c:\\agent\\dbg")

import vtrace
import vdb.stalker as stalker
import ToolbagTask

class libnotify(vtrace.Notifier):
    def notify(self, event, trace):
        libraryname = trace.getMeta("LatestLibraryNorm")
        if libraryname == "ws2_32":
            print "+++ caught the mswsock load"
        else:
            print "+++ loaded: %s" % libraryname

class task(ToolbagTask.ToolbagTask):
    def __init__(self, pkt, agentdata):
        self.pkt = pkt
        self.agentdata = agentdata
        ToolbagTask.ToolbagTask.__init__(self, pkt, agentdata)
    
    # override process
    def process(self, results):
        # results are a string, we know because we wrote the run() below :)
        print "+ RESULTS FROM AGENT: %s" % results
    
    # override run() to do something
    def run(self):
        trace = vtrace.getTrace()
        trace.execute("c:\\nc.exe -l -p 4040")
        trace.setMode("RunForever", True)
        notif = libnotify()
        trace.registerNotifier(vtrace.NOTIFY_LOAD_LIBRARY, notif)
        stalker.addStalkerEntry(trace, 0x00403047)
        while trace.isAttached():
            trace.run()

        hits = stalker.getStalkerHits(trace)

        for hit in hits:
            print "+ hit: %08x" % hit

        data = pickle.dumps(hits)
        self.sendResults(data)
        
        

    def prep(self):
        #import idc
        #print "PREP is hit and screen EA is 0x%08x" % idc.ScreenEA()
        pass
