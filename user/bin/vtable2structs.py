# vtable2structs.py
#
# for public release, 2012
#
# Aaron Portnoy


import idc
import idaapi
import idautils

from providers import ida

provider = ida.IDA()

text_start   = provider.segByBase(provider.segByName(".text"))
text_end     = provider.segEnd(provider.segByBase(provider.segByName(".text")))
vtable_start = 0


def myDemangle(addy):
    # XXX edit here for your custom demangling
    return idc.Name(addy)


jumpahead      = None
vtable_entries = []

vtables = {}

for head in idautils.Heads(text_start, text_end):

    if jumpahead != None:
        if head < jumpahead: 
            continue

    name = idc.Demangle(idc.Name(head), 0)

    if not name: continue

    if "vftable" in name:
        vtable_start = head

        # ghetto way to strip the "const foo::bar::`vftable`"
        name = name.split(" ")[1].split("::")[0]
        vtables[name] = []
    else:
        continue

    vtable_entries = []

    # XXX: max delta of 100 vtable entries, should be enough?
    for xhead in idautils.Heads(vtable_start, vtable_start+(4*100)):
        dref = list(idautils.DataRefsFrom(xhead))

        if dref == []:
            pass
        else:
            addy_flags = idc.GetFlags(dref[0])
            
            if (addy_flags & idc.FF_FUNC) != 0:
                vtable_entries.append(dref[0])

            else:
                vtable_start = 0
                jumpahead = xhead
                break

    if len(vtable_entries) > 1:
        vtables[name] = map(lambda x: myDemangle(x), vtable_entries)
  

###################################
# now create the structures
vcount = 0
ecount = 0
for k, vals in vtables.iteritems():
    struct_id = idc.AddStrucEx(-1, k, 0)
    vcount += 1
    for v in vals:
        ecount += 1
        idc.AddStrucMember(struct_id, v, -1, idc.FF_1OFF, -1, 4, -1, 0, idc.REF_OFF32)

print "[*] Created %d structures with a total of %d members" % (vcount, ecount)