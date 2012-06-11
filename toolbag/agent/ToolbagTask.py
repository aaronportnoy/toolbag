# ToolbagTask.py
#
# for public release, 2012
#
# Brandon Edwards


import os
import sys
import socket
import struct
import binascii
import toolbagcomm

#  
# ToolbagTask Class
# this is used by both the server and agent
# A task is created by deriving from this class
# please see Agent and Server documentation below

# For Agents:
# this class should be derived and have the run() method overridden 
# the run method should call sendResults (if/)when results are available
# once complete run should return

# For Server:
# a file containing the derived class is sent to the agent as a PYFILE opcode
# the agent will execute the run() method (which should always call sendResults)
# Upon receiving the results, processing/handling of the results is done with
# process()

# 
class ToolbagTask:
    # pkt is the ToolbagPacket representation of data from the server
    # agentdata is our data as a tuple (ip, port, key)
    def __init__(self, pkt, agentdata):
        self.pkt = pkt
        self.agentdata = agentdata

    # process()
    # process the results: this called by the toolbag server on the results
    # received in the queue from the agent (opcode: AGENTRESULTS)
    #
    # results are passed in from the msg from the packet received for RESULTS
    def process(self, results=None):
        if results == None:
            pass


    # sendResults()
    # this sends results back to the server: called by the agentside task
    #
    # results are the results
    # this sends results back to the server
    # with opcode being "agentresults" 
    # and filename echoing the task(file)name we were issued
    # 
    def sendResults(self, results):
        # subscribe to the server queue
        serverqueue = toolbagcomm.QueueClient(self.pkt.ip, self.pkt.port, self.pkt.key) 

        # build the packet
        packet = toolbagcomm.ToolbagPacket()

        # build out the header pieces
        packet.setPiece(ip=self.agentdata[0], port=self.agentdata[1], key=self.agentdata[2])

        resultsfilename = self.pkt.filename.split()[0] + ".results"
        packet.setPiece(opcode="agentresults", filename=resultsfilename)

        # add the results
        packet.setPiece(msg=results)

        # get the packet data
        rawpacket = packet.getPacket()
         
        # send it to the server 
        serverqueue.send(rawpacket)

        # done
        return

    # run()
    #
    def run(self):
        pass
        # send results to server
        # self.sendResults()
        return

    # this is preparation blah FIXME
    def prep(self):
        pass
