#!/usr/bin/env python
#
#
import os
import sys
import socket
import struct
import binascii
from multiprocessing import Process
from multiprocessing.managers import BaseManager
sys.path.append("%s%c%s" % (os.getcwd(), os.sep, "dbg"))

class Agent(BaseManager):
    pass
    
allofthethings = dict()

def writeFile(filename, data):
    # 'binary' must be specified for Windows
    "[*] writing %s [%i bytes]" % (filename, len(data))
    fd = open(filename, "wb")
    fd.write(data)
    fd.close()

# return data from file 
def readFile(filename):
    fd = open(filename, "rb")
    data = fd.read()
    fd.close()
    return data

def load(modulename):
    print "[*] loading module %s" % modulename
    module = __import__(modulename)
    allofthethings[modulename]=module

def get(objectname, attrname):
    print "[*] looking for attrname %s" % attrname
    attr = getattr(allofthethings[objectname], attrname)
    print str(type(attr))
    fullname = objectname+"_"+attrname
    print "[*] registering %s" % fullname
    Agent.register(str(fullname), attr)
    allofthethings[fullname]=attr
    return str(type(attr))

def runProcess(targetfunc, arguments, procname):
    runproc = Process(target=targetfunc, args=arguments)
    newproc.start()
    allofthethings[procname]=newproc

def debugPrint(s):
    print "[*] Message from controller: %s" % s

# main function
if __name__ == "__main__":
    argc = len(sys.argv)

    # First get arguments for AgentManager
    ip = sys.argv[1]
    port = sys.argv[2]
    key = sys.argv[3]

    print "[*] setting up agent on %s:%s [%s]" % (ip,port,key)

    print "[*] registering methods"
    Agent.register("get", get)
    Agent.register("load", load)
    Agent.register("readFile", readFile)
    Agent.register("writeFile", writeFile)
    Agent.register("printmsg", debugPrint)
    Agent.register("runProcess", runProcess)

    agent = Agent((ip,int(port)), authkey=key)
    print "[*] starting agent loop"
    server = agent.get_server()
    server.serve_forever()
    
    # exit
    sys.exit(0)
