# ida.py
#
# for public release, 2012
#
# Aaron Portnoy

import idc
import idaapi
import idautils

import base

import database
import function


form = idaapi.PluginForm

class IDA(base.Driver):


    # constants
    FUNC_FLAG = idc.FF_FUNC
    UI_Hooks = idaapi.UI_Hooks

    def currentEA(self):
        return idc.ScreenEA()

    def cxUp(self, ea):
        return database.cxup(ea)

    def cxDown(self, ea):
        return database.cxdown(ea)

    def getComment(self, ea):
        res = idc.GetCommentEx(ea, False)
        if not res:
            return ""
        else:
            return res

    def getRptComment(self, ea):
        return idc.GetCommentEx(ea, True)

    def addHotkey(self, key, handler):
        return idc.AddHotkey(key, handler)

    def demangleName(self, name):
        return idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN))

    def setColor(self, ea, color):
        return idc.SetColor(ea, idc.CIC_ITEM, color)    

    def getName(self, ea):
        return idc.Name(ea)

    def makeComment(self, ea, comment):
        return idc.MakeComm(ea, comment)

    def makeRptComment(self, ea, comment):
        return idc.MakeRptCmt(ea, comment)

    def getDisasm(self, ea):
        return idc.GetDisasm(ea)

    def getMnem(self, ea):
        return idc.GetMnem(ea)

    def iterInstructions(self, start, end):
        return idautils.Heads(start, end)

    def iterData(self, start, end):
        return idautils.Heads(start, end)

    def iterFuncChunks(self, ea):
        start = self.funcStart(ea)
        end   = self.funcEnd(ea)

        if not start or not end:
            return []

        current = idc.FirstFuncFchunk(start)
        chunks  = [current]

        while True:
            next = idc.NextFuncFchunk(start, current)
            
            if next != idc.BADADDR:
                current = next
                chunks.append(next)
            else:
                break

        res = []
        for chunk in chunks:
            chunk_end = idc.GetFchunkAttr(chunk, idc.FUNCATTR_END)
            res.extend(list(self.iterInstructions(chunk, chunk_end)))

        return res

    def funcStart(self, ea):
        try:
            func_item = idaapi.get_func(ea)
            if func_item:
                return func_item.startEA
            else: 
                return None
        except TypeError:
            return None

    def funcEnd(self, ea):
        func_item = idaapi.get_func(ea)
        if func_item:
            return func_item.endEA
        else:
            return None

    def registerTimer(self, interval, obj):
        return idaapi.register_timer(interval, obj)

    def unregisterTimer(self, obj):
        return idaapi.unregister_timer(obj)

    def compile(self, statement):
        return idaapi.CompileLine(statement)

    def segStart(self, ea):
        return idc.SegStart(ea)

    def getArch(self):
        return idaapi.get_idp_name()

    def isCode(self, ea):
        return idc.isCode(ea)

    def getFlags(self, ea):
        return idc.GetFlags(ea)

    def segEnd(self, selector):
        return idc.SegEnd(selector)

    def segByName(self, name):
        return idc.SegByName(name)

    def segByBase(self, selector):
        return idc.SegByBase(selector)

    def segName(self, selector):
        return idc.SegName(selector)

    def getSegments(self):
        return idautils.Segments()

    def nextItem(self, ea, bounds):
        return idc.NextHead(ea, bounds)

    def prevItem(self, ea, bounds):
        return idc.PrevHead(ea, bounds)

    def makeFunc(self, ea):
        return idc.MakeFunction(ea, idc.BADADDR)

    def getByte(self, ea):
        return idc.Byte(ea)

    def getWord(self, ea):
        return idc.Word(ea)

    def getDword(self, ea):
        return idc.Dword(ea)

    def getString(self, ea):
        stype = idc.GetStringType(ea)
        #if idaapi.is_unicode(stype):
        #    res = idc.GetString(ea, )
        return idc.GetString(ea, strtype=stype)

    def patchByte(self, ea, val):
        return idaapi.patch_byte(ea, val)

    def patchDword(self, ea, val):
        return idaapi.patch_long(ea, val)

    def isString(self, reference):
        return idc.isASCII(self.getFlags(reference))

    def refreshView(self):
        idaapi.refresh_idaview_anyway()

    # netnode crap
    def netnode(self, ident):
        return idaapi.netnode(ident)

    def numImports(self):
        return idaapi.get_import_module_qty()

    def importName(self, idx):
        return idaapi.get_import_module_name(idx)

    def basicBlockBoundaries(self, ea):
        func = idaapi.get_func(ea)
        flow = idaapi.FlowChart(func)        
        for block in flow:
            start = block.startEA
            end   = block.endEA

            if (ea < end) and (ea >= start):
                return (start, end)

    def enumImportNames(self, idx, func):
        return idaapi.enum_import_names(idx, func)

    def dataRefs(self, ea):
        return idautils.DataRefsFrom(ea)

    def scriptTimeout(self, timeout):
        return idaapi.set_script_timeout(timeout)

    def jumpto(self, addr):
        return idaapi.jumpto(addr)