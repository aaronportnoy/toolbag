# analysis.py
#
# for public release, 2012
#
# Kelly Lum

import idautils
import idaapi
import idc

class properties():

	def __init__(self, addr):
		self.addr = addr

	def funcProps(self): #build a dictionary using all the functions we've got
		props = {}
		props['isLeaf'] 	 = self.isLeaf()		
		props['numArgs'] 	 = self.argCount()
		props['xrefsTo'] 	 = self.countXrefsTo()
		props['isExport'] 	 = self.isExport()
		props['funcSize'] 	 = self.functionSize()	
		props['hasCookie'] 	 = self.hasCookie()	
		props['xrefsFrom'] 	 = self.countXrefsFrom()
		props['numBlocks'] 	 = self.countBlocks()
		props['numChunks'] 	 = self.countChunks()
		props['isRecursive'] = self.isRecursive()
		
		return props

	# needs some finesse, but... it's a steak...
	def hasCookie(self):
		end   = idc.GetFunctionAttr(self.addr, idc.FUNCATTR_END)
		start = idc.GetFunctionAttr(self.addr, idc.FUNCATTR_START)

		count = 0
		while((start != end) and (start != idc.BADADDR)):
			line = idc.GetDisasm(start)
			if line.startswith('xor'):
				if 'ebp' in line: 
					return True
			start = idc.NextAddr(start)
			count += 1
			# security cookie check is usually at beginning of function (unless some crazy-ass prologue)
			if (count > 20): return False
		return False


	def argCount(self): 
		end       = idc.GetFunctionAttr(self.addr, idc.FUNCATTR_END)
		start     = idc.GetFunctionAttr(self.addr, idc.FUNCATTR_START)
		frame     = idc.GetFrame(start)
		localv    = idc.GetFunctionAttr(self.addr, idc.FUNCATTR_FRSIZE)	
		frameSize = idc.GetFrameSize(start) #idc.GetStrucSize(frame)

		# offset to return
		try: 
			ret = idc.GetMemberOffset(frame, " r") 
		except:
			# error getting function frame (or none exists)
			return -1 
 
		if (ret < 0): return -1 

		firstArg = ret + 4 
		args  = frameSize - firstArg	
		numArgs = args / 4

		return numArgs

	def functionSize(self):
		return idc.GetFunctionAttr(self.addr, idc.FUNCATTR_END) - idc.GetFunctionAttr(self.addr, idc.FUNCATTR_START)

	def isExport(self):
		entries = idautils.Entries()

		for entry in entries:
			if self.addr in entry: return True
			
	 	return False

	def isLeaf(self):
		if (self.countXrefsFrom() == 0):	return True
		return False

	def isRecursive(self):
		return (self.addr in list(idautils.XrefsFrom(self.addr)))

	def countBlocks(self):
		return len(list(idaapi.FlowChart(idaapi.get_func(self.addr))))

	def countXrefsTo(self):
		return len(list(idautils.XrefsFrom(self.addr)))

	def countXrefsFrom(self):
		return len(list(idautils.XrefsTo(self.addr)))

	def countChunks(self): 
		return len(list(idautils.Chunks(self.addr)))

class search():
	def __init__(self, engine):
		#engine is a user-provided function that performs matching
		self.engine = engine  

	def matches(self, func_data):
		#return a subset of func_data that satisfies the matching engine
		matches = {}
		for func, func_info in func_data.iteritems():
			if func_info['attr']:
				exec(self.engine)
				res = myengine(func_info['attr'])
				if res: 
					matches[func] = func_info
		return matches	

		






