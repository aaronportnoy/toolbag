# segment.py
#
# for public release, 2012
#

'''
segment-context

generic tools for working with segments
'''
import idc,idautils,database,idaapi

def getName(ea):
    return idc.SegName(ea)

def getRange(ea):
    return idc.GetSegmentAttr(ea, idc.SEGATTR_START), idc.GetSegmentAttr(ea, idc.SEGATTR_END)

def get(name):
    for x in idautils.Segments():
        if getName(x) == name:
            return x
        continue
    raise KeyError(name)

def top(ea):
    return idc.GetSegmentAttr(ea, idc.SEGATTR_START)

def bottom(ea):
    return idc.GetSegmentAttr(ea, idc.SEGATTR_END)


def sameSegment(x, y):
	'''Returns true if x and y are within the same segment'''
	if idc.SegStart(x) == idc.SegStart(y): 
		return True
	else: 
		return False

def getSegsInfo():
	'''
	Returns a list of all segments in the form: (name, segstart, segend) 
	'''

	segments = list(idautils.Segments())

	res = []
	for s in segments:
		res.append((idc.SegName(s), idc.SegStart(s), idc.SegEnd(s)))
	
	return res

def realloc(ea, size, name=".newseg"):
	'''Deletes the segment for which 'ea' is a part of. Re-creates it with the given size and returns its base address'''

	# XXX: so, this is ghetto, but I'm going to leverage segment.alloc to create a 
	# new segment, steal its address, delete it, and move this segment there with a new size
	new_seg = alloc(size, name) 
	idc.SegDelete(new_seg, True)

	# move our existing segment
	idc.MoveSegm(ea, new_seg, True)
		
	# change its bounds
	idc.SetSegBounds(new_seg, new_seg, new_seg+size, True)

	return new_seg


def alloc(size, name):
	'''Allocates a segment of the given size.'''

	# first lets get the last segment in this binary
	last_seg_end = idaapi.get_last_seg().endEA

	# and the first
	first_seg_start = idaapi.get_first_seg().startEA

	# now see how many bytes we have from there to 0xFFFFFFFF
	bytes_high = 0xFFFFFFFF - last_seg_end

	# now see how many bytes we have from 0x0 to the first segments start  
	bytes_low = first_seg_start

	# check where we have more room
	if bytes_high > bytes_low:
		print "[*] segment.py: there is room above current segments"
		new_seg_start = last_seg_end + 0x10000
		new_seg_start = new_seg_start & 0xFFFF0000
	else:
		print "[*] segment.py: there is room below current segments"
		new_seg_start = 0 + 0x1000

	idc.SegCreate(new_seg_start, new_seg_start+size, 0, True, 3, 2)
	idc.SegRename(new_seg_start, name)
	
	return new_seg_start
