# base.py
#
# for public release, 2012
#
# Aaron Portnoy

class Driver(object):
    def currentEA(self):
        raise NotImplementedError

    def getComment(self, ea, **kwargs):
        raise NotImplementedError

    def getRptComment(self, ea, **kwargs):
        raise NotImplementedError        

    def makeComment(self, ea, comment, **kwargs):
        raise NotImplementedError

    def makeRptComment(self, ea, comment, **kwargs):
        raise NotImplementedError

    def getDisasm(self, ea, **kwargs):
        raise NotImplementedError

    def addHotkey(self, key, handler, **kwargs):
        raise NotImplementedError

    def demangleName(self, ea, **kwargs):
        raise NotImplementedError

    # XXX: not even sure what this should be called, just wrapping it
    def getLongPrm(self, type, **kwargs):
        raise NotImplementedError

    def setColor(self, ea, color, **kwargs):
        raise NotImplementedError

    def getName(self, ea, **kwargs):
        raise NotImplementedError

    def iterInstructions(self, start, end, **kwargs):
        raise NotImplementedError

    # XXX: idaapi.get_func
    def funcStart(self, ea, **kwargs):
        raise NotImplementedError

    def funcEnd(self, ea, **kwargs):
        raise NotImplementedError







