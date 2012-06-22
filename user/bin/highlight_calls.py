# highlight_calls.py
#
# for public release, 2012
#
# Aaron Portnoy

from idautils import XrefsFrom
from idaapi import fl_CN as call_near, fl_CF as call_far
from providers import ida

provider = ida.IDA()

startEA = provider.funcStart(provider.currentEA())
endEA = provider.funcEnd(provider.currentEA())

all_addresses = list(provider.iterInstructions(startEA, endEA))
all_addresses.extend(provider.iterFuncChunks(startEA))
all_addresses = list(set(all_addresses))

for head in all_addresses:
  for xref in XrefsFrom(head):
    if xref.type == call_near or xref.type == call_far:
      provider.setColor(head, 0x0000FF)

provider.refreshView()