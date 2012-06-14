# CopeEA.py
#
# for public release, 2012
#
# Peter Vreugdenhil


import idaapi
import idc
import ctypes
import re

print "Importing CopyEA"

def Paste( data ):
  strcpy = ctypes.cdll.msvcrt.strcpy
  ocb = ctypes.windll.user32.OpenClipboard    #Basic Clipboard functions
  ecb = ctypes.windll.user32.EmptyClipboard
  gcd = ctypes.windll.user32.GetClipboardData
  scd = ctypes.windll.user32.SetClipboardData
  ccb = ctypes.windll.user32.CloseClipboard
  ga = ctypes.windll.kernel32.GlobalAlloc    # Global Memory allocation
  gl = ctypes.windll.kernel32.GlobalLock     # Global Memory Locking
  gul = ctypes.windll.kernel32.GlobalUnlock
  GMEM_DDESHARE = 0x2000   
  ocb(None) # Open Clip, Default task
  ecb()
  hCd = ga( GMEM_DDESHARE, len(data)+1 )
  pchData = gl(hCd)
  strcpy(ctypes.c_char_p(pchData),data)
  gul(hCd)
  scd(1,hCd)
  ccb()


def CopyEA():
  myModuleName = idc.GetInputFile()
  MyModuleShortName = re.sub(r'\.[^.]*$','',myModuleName)
  myModuleBase = idaapi.get_imagebase()
  myOffset = idc.ScreenEA() - myModuleBase
  pasteStr = "bp !%s + 0x%x" % (MyModuleShortName, myOffset)
  print pasteStr
  Paste(pasteStr)


def start_up():
  print "CopyEA Start_up is started..."
  COPYHOTKEY = 'z'

  print "Press '%s' to copy location of effective address to clipboard()"%COPYHOTKEY
  idaapi.CompileLine('static _copy_ea() { RunPythonStatement("CopyEA()"); }')
  idaapi.add_hotkey(COPYHOTKEY,CopyEA)

start_up()
