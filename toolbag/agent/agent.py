# agent.py
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
from multiprocessing import Process

# tasks are processes actually doing shit like debugging something
tasks = list()

# first make sure we can kill this 
def shutdown(queueprocess):

    # kill the listening queue
    queueprocess.terminate()

    # get the tasks
    global tasks

    # for each tasks, kill it
    for task in tasks:
        task.terminate()

    sys.exit(0)


# this function imports the file specified in the ToolbagPacket
# the modules "run" method is called, and is provided with the
# packet we received which initiated this, as well as the agent's data
# after that, it is up to the class derived from ToolbagTask to do work
# and report back to the server
def runFile(pkt, agentdata):
    # import the filename 
    #(no .py for __import__())
    module =  __import__(pkt.filename.split('.py')[0])
    print "+ Importing: %s" % pkt.filename

    # instantiate the task
    task = module.task(pkt, agentdata)

    # call task run() method
    print "+ Running task.."
    task.run()

    # the module should do what it needs, once we hit here we are done
    # note: it is possible this is never reached
    #       such as in the conidition where a task runs indefinitely 
    #       (debugging, reporting back incrementally, etc), and is only
    #       killed once the tasks[index].terminate() is called via the 
    #       agent's shutdown method 
    
    # if we did return, delete the file
    print "+ Task complete"

    print "+ Deleting %s" % pkt.filename
    os.unlink(pkt.filename)

    return

# handler for a file exec request
# it takes a ToolbagPacket and the agent data
#
# this function writes the file contents to disk
# then spawns a new process and calls runFile()
def pyFileHandler(pkt, agentdata):

    # print (un)useful output
    print "+ file exec request for [%s] received from %s" % (pkt.filename, pkt.ip)
    print "+ filesize: %i bytes" % len(pkt.msg)

    # write to disk
    # this is ghetto, when we get fu working here we'll use that instead
    f = open(pkt.filename, "wb")
    f.write(pkt.msg)
    f.close()

    # setup a new process
    print "+ creating new task Process()"
    newproc = Process(target=runFile, args=(pkt, agentdata))
    # before launching add it to tasks lists
    global tasks
    tasks.append(newproc)

    # run it
    newproc.start()
    return

# main function
if __name__ == "__main__":
    argc = len(sys.argv)

    if argc < 4:
        print "Usage: %s <ip> <port> <key>" % sys.argv[0]
        sys.exit(0)

    ip = sys.argv[1]
    port = sys.argv[2]
    key = sys.argv[3]

    # agent queue data 
    agentdata = (ip, port, key)
    
    # tasks list
    tasks = list()

    # start up listening queue
    print "+ Starting listening queue"
    queueprocess = Process(target=toolbagcomm.QueueServer, args=agentdata)
    queueprocess.start()

    # setup agent class
    print "+ Setting up ToolbagAgent"
    agent = toolbagcomm.ToolbagAgent(ip, port, key) 

    # register callbacks
    print "+ Registerng callbacks"
    # first callback: DIE, ability to kill the agent
    agent.registerCallback("DIE", shutdown, args=(queueprocess))

    # callback for file handler
    agent.registerCallback("PYFILE", pyFileHandler, None)

    print "+ Entering main loop"
    agent.mainLoop()
    
    # exit
    sys.exit(0)
