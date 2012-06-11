#!/usr/bin/env python
#
#
import os
import sys
import socket
import struct
import binascii
import toolbagcomm
from multiprocessing import Process

def waitfordata(host):
    while 1:
        print "+ waiting for data..."
        data = host.recv()
        pkt = toolbagcomm.ToolbagPacket(data)
        print "+ %s:%i[%s] sent us %s %s" % (pkt.ip, pkt.port, pkt.key, pkt.opcode, pkt.filename)

# main function
if __name__ == "__main__":
    argc = len(sys.argv)

    ip = sys.argv[1]
    port = sys.argv[2]
    key = sys.argv[3]

    host = toolbagcomm.ToolbagHost(None, "server.py", ip, port, key)
    p = Process(target=waitfordata, args=(host,))
    p.start() 

    print "+ add agent as ip.ip.ip.ip port key"
    print "+ add agent> "
    
    agentinput = sys.stdin.readline().split()
    agentip = agentinput[0]
    agentport = agentinput[1]
    agentkey = agentinput[2]
    host.addAgent(agentip, agentport, agentkey)
    
    # exit
    sys.exit(0)
