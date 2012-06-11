# __init__.py
#
# for public release, 2012
#
# Aaron Portnoy


# Standard Libraries
import os
import sys

#
from ui import UI
from db import DB

import RefTree
from config import *

from providers import ida

from PySide import QtCore, QtGui


class ToolBag:
    def __init__(self, options):

        self.provider = ida.IDA()

        # show splash screen
        # 
        # this will only really be shown when toolbag is loaded for the first time
        # as when we initialize our PluginForm-subclassed object (UI), it wipes it
        if options['show_splash']:
            splash_image = options['ida_user_dir'] + os.sep + "rsrc" + os.sep + "splash.png"
            pixmap = QtGui.QPixmap(splash_image)
            splash = QtGui.QSplashScreen(pixmap)
            splash.show()

        if options['file_system_type'] == 'netnode':
            from fs_nn import FS
        elif options['file_system_type'] == 'segment':
            from fs import FS
        else:
            print "[!] Invalid 'file_system_type' specified in the config options"
            return

        # file system must be initialized first as db requires it
        self.filesystem = FS(options)
        
        print '[*] __init__.py: loading DB file from disk'
        # try to see if its on disk already
        try:
            fh = open(options['full_file_name'], 'rb')
            dbfile = fh.read()
            fh.close()
            self.db = DB(options, create=False, existing=dbfile)
        except:
            print "[!] Unable to load the database file on disk at %s" % options['full_file_name']
            print "[*] Creating a new database file on disk"
            self.db = DB(options, create=True)
        
        self.reftree = RefTree.RefTree(self.db)
        self.ui = UI(self.reftree, self.filesystem, self.db, options)
        self.ui.global_hook = self

        self.retvals = {}

        self.ui.Show("Toolbag")
        
        if options['show_splash']:
            try:
                _script = __import__("utils")
            except Exception as detail:
                print detail
     

    def getContext(self):
        res = {}
        res["ui"] = self.ui
        res["db"] = self.db
        res["fs"] = self.filesystem
        res["reftree"] = self.reftree
        return res



print '[*] Initializing Toolbag'
print '-'*80
print "[*] Options:"
for k,v in options.iteritems():
    print "        %s => %s" % (k,v)
print '-'*80

toolbag = ToolBag(options)
