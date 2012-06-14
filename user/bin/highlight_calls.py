# highlight_calls.py
#
# for public release, 2012
#
# Aaron Portnoy


from providers import ida

provider = ida.IDA()

startEA = provider.funcStart(provider.currentEA())
endEA = provider.funcEnd(provider.currentEA())

all_addresses = list(provider.iterInstructions(startEA, endEA))
all_addresses.extend(provider.iterFuncChunks(startEA))
all_addresses = list(set(all_addresses))

for head in all_addresses:
  disasm = provider.getDisasm(head)

  if disasm.startswith("call"):
    provider.setColor(head, 0x0000FF)

provider.refreshView()