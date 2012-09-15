#!/usr/bin/env python
# 
#
from multiprocessing.managers import BaseManager

class Illusion:
    def __init__(self, name, agent):
        self.name = name
        self.agent = agent
        self.localattrs = dict()

    def __getattr__(self, item):
#        print "illusion __getattr__ %s" % item
        thetype = self.agent.get(self.name, item)._getvalue()
#        print "the type: %s" % thetype
        accepted = list()
        accepted.append("<type 'instancemethod'>")
        accepted.append("<type 'classobj'>")
        accepted.append("<type 'function'>")
        fullname=self.name+"_"+item

        if thetype in accepted:
#            print "found accepted type..."
            AgentManager.register(fullname)
            return getattr(self.agent, fullname)

        else:
#            print "returning an illusion"
            return Illusion(fullname, self.agent)
        
# AganetBase: extends BaseManager 
# this is test out using disconnect with the built-in connect
# the idea is to avoid connection timeouts, and instead of 
# changing the default timeout value, to just connect/disconnect
# before/after each use of the networked manager
class AgentManager(BaseManager):
    def __init__(self, address, authkey):
        BaseManager.__init__(self, address, authkey)
        self.srvAddr = address
        self.srvKey = authkey

        AgentManager.register("get")
        AgentManager.register("load")
        AgentManager.register("readFile")
        AgentManager.register("writeFile")
        AgentManager.register("printmsg")

        self.localattrs = dict()

    def loadmodule(self, modulename):
        print "[*] loading module %s" % modulename
        self.load(modulename)
        self.localattrs[modulename] = Illusion(modulename, self)
        
    def __getattr__(self, item):
        if item in self.localattrs.keys():
            return self.localattrs[item]

    # disconnect
    def disconnect(self):
        conn = self._Client(self.srvAddr, self.srvKey)
        conn.close()

