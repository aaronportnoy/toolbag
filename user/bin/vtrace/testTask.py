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


import ToolbagTask

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
        # simulate execution time by sleeping for 20 seconds
        time.sleep(5)
        results = "+ address 0x41414141 breakpoint hit 20 times"

        # write a logfile to disk on the agent side, log results
        f = open("TaskResults.txt", "w")        
        f.write("+ Task simulation\n")
        f.write("+ Task results: %s" % results)
        f.close()
        # 
        # send results to server
        self.sendResults(results)

    def prep(self):
        import idc
        print "PREP is hit and screen EA is 0x%08x" % idc.ScreenEA()
