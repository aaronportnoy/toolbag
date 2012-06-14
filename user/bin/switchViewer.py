import idautils
import idaapi
import idc

switches = []

for f in idautils.Functions():
    func = idaapi.get_func(f)

    for h in idautils.Heads(func.startEA, func.endEA):
        opcodes = idc.Dword(h) & 0xFFFF
        if opcodes == 0x24ff:
            # number of cases
            res = idaapi.get_switch_info_ex(h)
            if res != None:
                num_cases = res.get_jtable_size()
            else:
                continue

            print '0x%08x: switch (%d cases)' % (h, num_cases)

            # get cases
            xrefs = idautils.CodeRefsFrom(h, 1)


            interesting_calls = []
            
            switches.append((h, num_cases, interesting_calls))




# http://dvlabs.tippingpoint.com/blog/2011/05/11/mindshare-extending-ida-custviews
class SwitchViewer(idaapi.simplecustviewer_t):

    def __init__(self, data):

        # data should be a 3-tuple
        #
        # (address, number of cases, list of interesting calls)
        self.switches = data

        # we define a dictionary, keyed by address
        # values will be the interesting calls
        self.calls = {}
        self.Create()
        print "Launching Switch subview..."
        self.Show()

    def Create(self):
        title = "Switches"

        idaapi.simplecustviewer_t.Create(self, title)
        comment = idaapi.COLSTR("; Double-click to follow", idaapi.SCOLOR_BINPREF)

        self.AddLine(comment)

        #comment = idaapi.COLSTR("; Hover for preview", idaapi.SCOLOR_BINPREF)
        comment = ""

        self.AddLine(comment)

        for item in self.switches:
            addy = item[0]
            cases = item[1]
            interesting_calls = item[2]
            self.calls[addy] = interesting_calls

            address_element = idaapi.COLSTR("0x%08x: " % addy, idaapi.SCOLOR_REG)
            value_element = idaapi.COLSTR("%s" % cases, idaapi.SCOLOR_STRING)
            line = address_element + value_element

            self.AddLine(line)

        return True

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        if "0x" not in line: return False

        # skip COLSTR formatting, find address

        addy = int(line[2:line.find(":")], 16)

        idc.Jump(addy)
        return True 

    def OnHint(self, lineno):
        if lineno < 2: return False
        else: lineno -= 2

        line = self.GetCurrentLine()

        if "0x" not in line: return False

        # skip COLSTR formatting, find address

        addy = int(line[2:line.find(":")], 16)

        calls = self.calls[addy]

        res = ""
        for line in calls:
            res += idaapi.COLSTR(line + "\n", idaapi.SCOLOR_DREF) 

        return (1, res)

SwitchViewer(switches)