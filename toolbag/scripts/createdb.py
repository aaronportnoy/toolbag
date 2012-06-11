# createdb.py
#
# for public release, 2012
#
# Aaron Portnoy
#
# C:\>"C:\Program Files (x86)\ida\idaw.exe" -A -OIDAPython:createdb.py calc.exe
#


# Standard Libraries
import os
import sys

# IDA
import idc
import idaapi


sys.path.append(os.environ['USERPROFILE'] + "\\AppData\\Roaming\\Hex-Rays\\IDA Pro\\toolbag")

from config import *
import RefTree

# 
from db import DB

idaapi.autoWait()
dbobj = DB(options, create=True)
idc.Exit(0)
