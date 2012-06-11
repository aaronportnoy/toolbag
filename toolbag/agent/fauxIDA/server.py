# server.py
#
# for public release, 2012
#
# Brandon Edwards



# Standard Libraries
import os
import sys
import time
import socket
import signal
import struct
import binascii

#
import toolbagcomm


# we had a promise made 
def usage(s):
    print "+ usage %s <ip> <port> <key>" % s

# main function
if __name__ == "__main__":

    argc = len(sys.argv)

    ip = sys.argv[1] 
    port = int(sys.argv[2])
    key = sys.argv[3]

#    sys.stdout = open("c:\\log2.txt", "w")
#    sys.stderr = sys.stdout

    print "[*] Setting up Toolbag Queue Server"
    myserv = toolbagcomm.QueueServer(ip, port, key)
        
