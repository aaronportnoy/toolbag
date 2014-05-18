# CopeEA.py
#
# for public release, 2012
#
# Peter Vreugdenhil


import idaapi
import idc
import ctypes
import re
from PySide import QtGui

print "Importing CopyEA"

def CopyEA():
  myModuleName = idc.GetInputFile()
  MyModuleShortName = re.sub(r'\.[^.]*$','',myModuleName)
  myModuleBase = idaapi.get_imagebase()
  myOffset = idc.ScreenEA() - myModuleBase
  clippy = QtGui.QClipboard()
  pasteStr = "bp !%s + 0x%x" % (MyModuleShortName, myOffset)
  print pasteStr
  clippy.setText(pasteStr)


def start_up():
  print "CopyEA Start_up is started..."
  COPYHOTKEY = 'z'

  print "Press '%s' to copy location of effective address to clipboard()"%COPYHOTKEY
  idaapi.CompileLine('static _copy_ea() { RunPythonStatement("CopyEA()"); }')
  idaapi.add_hotkey(COPYHOTKEY,CopyEA)

start_up()
