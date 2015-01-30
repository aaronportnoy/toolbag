# ui.py
#
# for public release, 2012
#
# Aaron Portnoy


# Standard Libraries
import os
import re
import sys
import time
import copy
import pickle
import atexit
import socket
import signal
import getpass
import tempfile
import traceback
import subprocess
import types

# PySide
from PySide import QtCore, QtGui

# Toolbag stuff
import segment
import RefTree
import database
import function
import pathfinder
import analysis

# Remote communication
#import toolbagcomm
#import ToolbagTask

# IDA provider
from providers import ida
from providers.ida import form as PluginForm


class PeerDataQueue:
    def __init__(self):
        self.stack = []
        self.current_id = 0


    def add(self, ip, objname, objtype, data, id_):
        self.stack.append((ip, objname, objtype, data, id_))
        self.current_id += 1


    def remove(self, data):
        tmp = []
        for item in self.stack:

            x = self.fetchattr(item, 'data')
            
            if x == data:
                print "[*] Removed item from the peer data queue"
            else:
                tmp.append(item)

        self.stack = tmp


    def fetchitem(self, id_):
        for i in self.stack:
            attr = self.fetchattr(i, "id")
            if id_ == attr:
                return i


    def fetchattr(self, item, param):
        if param == 'ip':
            return item[0]
        elif param == "objname":
            return item[1]
        elif param == "objtype":
            return item[2]
        elif param == "data":
            return item[3]
        elif param == "id":
            return item[4]
        else:
            print "[!] PeerDataQueue::fetchattr failed..."
        

    def newid(self):
        return self.current_id+1


###############################################################################
class Applier(PluginForm):
    def __init__(self, ui_obj, selected, op):
        self.op = op
        self.selected = selected
        self.ui_obj = ui_obj

        self.provider = ida.IDA()

        super(Applier, self).__init__()


    def OnCreate(self, form):
        self.myform = form
        self.parent = self.FormToPySideWidget(form)
        self.PopulateForm()


    def PopulateForm(self):

        layout = QtGui.QVBoxLayout()

        if self.op == "cmts" or self.op == "rcmts":
            cmts = pickle.loads(self.ui_obj.fs.load(self.selected))

            # they came out of the trees man... the trees!
            cmts_tree_widget = QtGui.QTreeWidget()
            cmts_tree_widget.setHeaderLabels(("Address", "Old", "New", "Conflicted"))
            cmts_tree_widget.setColumnCount(4)
            cmts_tree_widget.setColumnWidth(0, 110)
            cmts_tree_widget.setColumnWidth(1, 250)
            cmts_tree_widget.setColumnWidth(2, 250)
            cmts_tree_widget.setColumnWidth(3, 20)
            cmts_tree_widget.setSortingEnabled(True)
            cmts_tree_widget.setSelectionMode(QtGui.QAbstractItemView.ExtendedSelection)
            self.cmts_tree_widget = cmts_tree_widget

            button_group     = QtGui.QWidget()
            button_container = QtGui.QHBoxLayout()
            button_container.addStretch(1)
            button_group.setLayout(button_container)

            select_all = QtGui.QPushButton("Select All")
            select_all.clicked.connect(self.selectAll)

            clear = QtGui.QPushButton("Clear Selection")
            clear.clicked.connect(self.clearSelection)

            apply_selected = QtGui.QPushButton("Apply Selected")
            apply_selected.clicked.connect(self.applySelected)

            button_container.addWidget(select_all)
            button_container.addWidget(clear)
            button_container.addWidget(apply_selected)
            button_container.addStretch(1)

            optional_group     = QtGui.QWidget()
            optional_container = QtGui.QHBoxLayout()
            optional_container.addStretch(1)
            optional_group.setLayout(optional_container)

            prefix_label = QtGui.QLabel()
            prefix_label.setText("Prefix:")

            prefix_input = QtGui.QLineEdit()
            prefix_input.setPlaceholderText("optional")

            self.prefix_input = prefix_input

            optional_container.addWidget(prefix_label)
            optional_container.addWidget(prefix_input)

            layout.addWidget(cmts_tree_widget)
            layout.addWidget(optional_group)
            layout.addWidget(button_group)
            self.parent.setLayout(layout)

            for k, v in cmts.iteritems():
                self.processCmt(k, v)
        
        elif self.op == "names":
            # XXX: to dev later
            pass


    def processCmt(self, address, comment):
        # test if there exists a comment at the address
        current = ""
        if self.op == "cmts":
            current = self.provider.getComment(address)

        elif self.op == "rcmts":
            current = self.provider.getRptComment(address)
        
        if current != comment and current != None:
            item = QtGui.QTreeWidgetItem(self.cmts_tree_widget)
            if self.ui_obj.options['architecture'] == "32":
                item.setText(0, "0x%08x" % address)
            else:
                item.setText(0, "0x%016x" % address)
            item.setText(1, current)
            item.setText(2, comment)
            item.setText(3, "YES")
            return

        # no conflict
        if current == None or current == comment:
            item = QtGui.QTreeWidgetItem(self.cmts_tree_widget)
            if self.ui_obj.options['architecture'] == "32":
                item.setText(0, "0x%08x" % address)
            else:
                item.setText(0, "0x%016x" % address)

            if current == comment:
                item.setText(1, current)
            else:
                item.setText(1, "")

            item.setText(2, comment)
            item.setText(3, "NO")
            return


    def selectAll(self):
        if self.op == "cmts" or self.op == "rcmts":
            count = self.cmts_tree_widget.topLevelItemCount()

            for i in xrange(0, count):
                item = self.cmts_tree_widget.topLevelItem(i)
                item.setSelected(True)


    def clearSelection(self):
        if self.op == "cmts" or self.op == "rcmts":
            count = self.cmts_tree_widget.topLevelItemCount()

            for i in xrange(0, count):
                item = self.cmts_tree_widget.topLevelItem(i)
                item.setSelected(False)


    def applySelected(self):
        if self.op == "cmts" or self.op == "rcmts":
            items = self.cmts_tree_widget.selectedItems()
            for i in items:
                address = int(i.text(0), 16)

                # unicode -> str
                comm = str(i.text(2))

                prefix = str(self.prefix_input.text())
                comm = prefix + " " + comm

                if self.op == "cmts":
                    self.provider.makeComment(address, comm)
                else:
                    self.provider.makeRptComment(address, comm)


    def OnClose(self, form):
        pass


###############################################################################

class Analysis(PluginForm):
    def __init__(self, ui_obj):
        self.ui_obj = ui_obj
        self.provider = ida.IDA()
        self.font    = QtGui.QFont(self.ui_obj.options['font_name'], int(self.ui_obj.options['font_size']))
        self.bgbrush = QtGui.QBrush(QtGui.QColor(self.ui_obj.options['background_color']))
        self.fgbrush = QtGui.QBrush(QtGui.QColor(self.ui_obj.options['font_color']))
        
        # order matters so using two lists instead of a dict
        self.labels = \
        ['Name', 'Address', 'Args', 'Size', 'Xrefs To', 'Xrefs From', 'Blocks', 'Chunks', 'Cookie' , 'Recursive', 'Export', 'Leaf']
        self.keynames = \
        ['numArgs', 'funcSize', 'xrefsTo', 'xrefsFrom', 'numBlocks', 'numChunks', 'hasCookie', 'isRecursive', 'isExport', 'isLeaf']

        self.default_engine_str = \
'''
### Provide a 'matching engine' myengine(attr) that will return True for functions with desirable attributes.
### Attributes are stored in the 'attr' dictionary. The keys and the respective data types returned are:
# numArgs, funcSize, xrefsFrom, xrefsTo, numBlocks, numChunks: <int>
# hasCookie, isRecursive, isExport, isLeaf: <boolean>
### An example query is below which return non-recursive functions with more than 2 arguments

def myengine(attr): 
    return ((attr['numArgs'] > 2) and (attr['isRecursive'] == False))
'''
        self.engine_str = self.default_engine_str

        super(Analysis, self).__init__()


    def OnCreate(self, form):
        self.parent = self.FormToPySideWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        layout = QtGui.QVBoxLayout()
        self.layout = layout

        self.textbox = QtGui.QPlainTextEdit()
        p = self.textbox.palette()
        p.setColor(QtGui.QPalette.Base, self.ui_obj.options['background_color'])
        p.setColor(QtGui.QPalette.WindowText, self.ui_obj.options['font_color'])

        self.textbox.setPalette(p)
        self.textbox.setFont(self.font)
        self.textbox.setPlainText(self.engine_str)

        button_container = QtGui.QHBoxLayout()
        button_group     = QtGui.QWidget()
        button_group.setLayout(button_container)

        execbutton = QtGui.QPushButton("Execute")
        execbutton.clicked.connect(self.setEngine)
        button_container.addStretch(1)
        button_container.addWidget(execbutton)
        button_container.addStretch(1)

        export_container = QtGui.QHBoxLayout()
        export_group     = QtGui.QWidget()
        export_group.setLayout(export_container)

        export_button = QtGui.QPushButton("Export")
        export_button.clicked.connect(self.exportData)
        export_container.addStretch(1)
        export_container.addWidget(export_button)
        export_container.addStretch(1)

        # populate the table
        self.makeTable(isNew=True)

        layout.addWidget(self.textbox)
        layout.addWidget(button_group)
        layout.addWidget(self.table)
        layout.addWidget(export_group)

        self.parent.setLayout(layout)


    def clearTable(self):
        rows = self.table.rowCount() 
        cols = self.table.columnCount()

        for i in reversed(xrange(0, rows)):
            print self.table.removeRow(i)

        for i in reversed(xrange(0, cols)):
            self.table.removeColumn(i)

    def pretty(self, val):
        # construct user-friendly strings
        if type(val) is types.BooleanType:
            if val: return "Y"
            return "N"
        
        if val == -1:
            return "?"

        return str(val)

    def setEngine(self):
        engine_str = self.textbox.document().toPlainText()
        self.engine_str = engine_str
        self.textbox.setPlainText(self.engine_str)
        self.clearTable()
        self.makeTable()


    def makeTable(self, isNew=False):
        # turn our user-supplied string into an exec-able function
        code_obj = compile(self.engine_str, '<string>', 'exec')
        self.engine = code_obj
 
        # get the function data from inside this nightmarish hellscape
        func_data = self.ui_obj.master.function_data
        search_data = analysis.search(self.engine)
        try:
            hits = search_data.matches(func_data)
            # for the export
            self.lasthits = hits
        except Exception as detail:

            self.engine_str = "# What the hell was that? Not a valid matching engine!\n"
            self.engine_str += "\n" + self.default_engine_str
            self.textbox.setPlainText(self.engine_str)
            
            if not isNew:
                self.setEngine()
            return

        num_rows = len(hits)
        num_cols = len(self.labels)
        
        if(isNew):
            self.table = QtGui.QTableWidget(num_rows, num_cols)
        else:
            self.table.setColumnCount(num_cols)
            self.table.setRowCount(num_rows)    

        row = 0
        for func, func_info in hits.iteritems():
            col = 0
            attrs = func_info['attr']
            if attrs:
                func_name = self.provider.getName(func)
                func_name = self.provider.demangleName(func_name)

                if not func_name:
                    func_name = self.provider.getName(func)
                
                item = self.makeItem(func_name)
                item.setTextAlignment(QtCore.Qt.AlignLeft) 
                item.setTextAlignment(QtCore.Qt.AlignVCenter)
                self.table.setItem(row, col, item)
                col += 1
                
                func = self.pretty(hex(func))
                item = self.makeItem(func)
                self.table.setItem(row, col, item)
                col += 1

                for k in self.keynames:
                    val = self.pretty(attrs[k])
                    item = self.makeItem(val)
                    self.table.setItem(row, col, item)
                    col += 1
                row += 1
       
        self.table.itemDoubleClicked.connect(self.itemDoubleClicked)
        self.table.setHorizontalHeaderLabels(self.labels)
        self.table.setSortingEnabled(True)
    
    def itemDoubleClicked(self, item):
        # in function address column
        if item.column() == 1:
            self.provider.jumpto(int(item.text(), 16))

    def makeItem(self, itemStr):
        item = QtGui.QTableWidgetItem(itemStr)
        item.setFont(self.font)
        item.setForeground(self.fgbrush)
        item.setBackground(self.bgbrush)
        # center
        item.setTextAlignment(QtCore.Qt.AlignCenter)

        return item

    def exportData(self):
        # do somethin' britney spears muthafucka
        text = QtGui.QInputDialog().getText(None, "Export Results", "Enter filename:")
        filename = str(text[0])
        tmp = tempfile.TemporaryFile(mode='wb')
        tmpname = tmp.name
        tmp.close()

        lasthits_tree = RefTree.RefTree(masterGraph=self.ui_obj.master, function_data=self.lasthits)

        pickled_file = open(tmpname, "wb")
        pickle.dump(lasthits_tree, pickled_file)
        pickled_file.close()

        fh = open(tmpname, "rb")
        tablehit_data = fh.read()
        fh.close()

        self.ui_obj.fs.store(filename, tablehit_data)
        self.ui_obj.refreshFilesystem()
        return

    def onClose(self, form):
        #um wat
        return

###############################################################################


class Query(PluginForm):
    def __init__(self, ui_obj, start, depth):
        self.ui_obj = ui_obj

        if depth < 0:
            depth = abs(depth)
            results = self.ui_obj.master.queryDepth(start, depth, direction='up')
        else:
            results = self.ui_obj.master.queryDepth(start, depth, direction='down')

        if results == []:
            self.addrs = [start]
        else:
            self.addrs = [start]
            self.addrs.extend(results)

        self.provider = ida.IDA()

        super(Query, self).__init__()


    def OnCreate(self, form):
        self.myform = form
        self.parent = self.FormToPySideWidget(form)
        self.PopulateForm()


    def PopulateForm(self):
        addrs           = self.addrs
        layout          = QtGui.QVBoxLayout()
        query_tree      = RefTree.RefTree(self.ui_obj.master)
        self.query_tree = query_tree

        for a in addrs:
            query_tree.add_func(a)
        
        query_tree_widget = QtGui.QTreeWidget()
        query_tree_widget.setHeaderLabels(("Name", "Address"))
        query_tree_widget.setColumnCount(2)
        query_tree_widget.setColumnWidth(0, 500)
        query_tree_widget.setColumnWidth(1, 40)
        query_tree_widget.setSortingEnabled(True)
        self.query_tree_widget = query_tree_widget

        query_tree_widget.itemClicked.connect(self.itemClicked)

        try:
            for graph in query_tree.makeTrees():
                self.ui_obj.createChildrenItems(graph, query_tree_widget)
        except RuntimeError as detail:
            print "[!] Error creating graph object: %s" % detail
            return

        self.query_tree = query_tree

        bgbrush = QtGui.QBrush(QtGui.QColor(self.ui_obj.options['background_color']))
        palette = QtGui.QPalette()

        v = query_tree_widget.viewport()
        palette.setBrush(v.backgroundRole(), bgbrush)
        v.setPalette(palette)

        search_group     = QtGui.QWidget()
        search_container = QtGui.QHBoxLayout()
        search_group.setLayout(search_container)

        search = QtGui.QLabel()
        search.setText("Search Disassembly:")
        search_container.addWidget(search)

        search_input      = QtGui.QLineEdit()
        self.search_input = search_input
        search_input.setPlaceholderText("enter search term, things like: 'movsx', 'malloc', '[eax+'")
        search_input.returnPressed.connect(self.doSearch)
        search_container.addWidget(search_input)

        search_button = QtGui.QPushButton("Search")
        search_button.clicked.connect(self.doSearch)
        search_container.addWidget(search_button)

        clear_button = QtGui.QPushButton("Clear")
        clear_button.clicked.connect(self.clearSearch)
        search_container.addWidget(clear_button)

        save_button = QtGui.QPushButton("Save")
        save_button.clicked.connect(self.saveAsSess)
        search_container.addWidget(save_button)

        #freeform_radio = QtGui.QRadioButton()
        #freeform_radio.setText("Free Form")
        regex_checkbox = QtGui.QCheckBox()
        regex_checkbox.setText("Regex?")
        search_container.addWidget(regex_checkbox)

        self.reCheck = regex_checkbox

        self.treewidget = query_tree_widget

        layout.addWidget(search_group)
        layout.addWidget(query_tree_widget)
        self.parent.setLayout(layout)       


    def OnClose(self, form):
        del(self.query_tree)


    def itemClicked(self, item, column):

        col2_data = item.data(1,0)
        try:
            addr = int(col2_data, 16)
            database.go(addr)
            #self.refreshMarks(self.db, local=True)

            if self.ui_obj.show_imports == True:
                self.ui_obj.refreshImports()
            if self.ui_obj.show_strings == True:
                self.ui_obj.refreshStrings()

        except Exception as detail:
            print '[!] Failed to jump to address clicked in query tree, %s' % detail
            pass


    def match(self, widgetitem, param):

        # fuckin' rainbows, man
        bgbrush = QtGui.QBrush(QtGui.QColor('darkgreen'))
        fgbrush = QtGui.QBrush(QtGui.QColor('white'))

        if widgetitem.text(1) == param:
            widgetitem.setForeground(0, fgbrush)
            widgetitem.setForeground(1, fgbrush)
            widgetitem.setBackground(0, bgbrush)
            widgetitem.setBackground(1, bgbrush)

        for childidx in xrange(0, widgetitem.childCount()):
            self.match(widgetitem.child(childidx), param)      


    def clearSearch(self):
        treewidget = self.treewidget
        query_tree = self.query_tree

        treewidget.clear()

        try:
            for graph in query_tree.makeTrees():
                self.ui_obj.createChildrenItems(graph, treewidget)
        except RuntimeError as detail:
            print "[!] Error creating graph object: %s" % detail
            return

        bgbrush = QtGui.QBrush(QtGui.QColor(self.ui_obj.options['background_color']))
        palette = QtGui.QPalette()

        v = treewidget.viewport()
        palette.setBrush(v.backgroundRole(), bgbrush)
        v.setPalette(palette)


    def doSearch(self):
        self.clearSearch()

        params     = self.search_input.text()
        treewidget = self.treewidget
        query_tree = self.query_tree

        if self.reCheck.isChecked():
            re_obj = re.compile(params, re.IGNORECASE)
        
        addrs = query_tree.function_data.keys()

        bgbrush = QtGui.QBrush(QtGui.QColor(self.ui_obj.options['highlighted_background']))
        fgbrush = QtGui.QBrush(QtGui.QColor(self.ui_obj.options['highlighted_foreground']))

        RE = False
        if self.reCheck.isChecked():
            RE = True

        found = False
        for a in addrs:
            startEA = self.provider.funcStart(a)
            endEA = self.provider.funcEnd(a)
            
            for h in self.provider.iterInstructions(startEA, endEA):
                disasm = self.provider.getDisasm(h)
            
                if RE:
                    matches = re.match(re_obj, disasm)
                    if matches:
                        matches = matches.group()
                    if matches != None:
                        found = True
                    else:
                        continue
                try:
                    if found or (params in disasm):

                        # find it in the treewidget and color it
                        toplevelcount = treewidget.topLevelItemCount()
                        for i in xrange(0, toplevelcount):
                            toplevelitem = treewidget.topLevelItem(i)
                            addy = toplevelitem.text(1)
                            
                            if startEA == None:
                                continue

                            if self.ui_obj.options['architecture'] == "32":
                                
                                if addy == "0x%08x" % startEA:
                                    toplevelitem.setForeground(0, fgbrush)
                                    toplevelitem.setForeground(1, fgbrush)
                                    toplevelitem.setBackground(0, bgbrush)
                                    toplevelitem.setBackground(1, bgbrush)

                                self.match(toplevelitem, "0x%08x" % startEA)

                            else:
                                if addy == "0x%016x" % startEA:
                                    toplevelitem.setForeground(0, fgbrush)
                                    toplevelitem.setForeground(1, fgbrush)
                                    toplevelitem.setBackground(0, bgbrush)
                                    toplevelitem.setBackground(1, bgbrush)

                                self.match(toplevelitem, "0x%016x" % startEA)


                        # done with this function if we found at least one match
                        found = False
                        break
                except UnicodeDecodeError:
                    continue


    def saveAsSess(self):
        self.ui_obj.saveHistory(userRefTree=self.query_tree)
        
        
###############################################################################

class UI(PluginForm):
    """
    Main class responsible for the Toolbag UI
    """

    def __init__(self, tree, fs, master, options):
        """
        Initializes the UI

        @type   tree:       object
        @param  tree:       RefTree used to generate trees in PySide QTreeView widgets

        @type   fs:         object
        @param  fs:         toolbag.FS file system object

        @type   master:     object
        @param  master:     toolbag.RefTree.MasterReftree object

        @type   options:    dict
        @param  options:    Dictionary containing the options read from config.py and userconfig.py
        
        """
        
        self.fs                 = fs
        self.peers              = []
        self.agent              = None
        self.master             = master
        self.reftree            = tree
        self.options            = options
        self.peerdata           = PeerDataQueue()
        self.last_history_added = None

        print self.reftree


        # using this as a locking mechanism
        # so that if a user tries to use something from
        # a right-click context menu, none of the timers 
        # will re-draw widgets while this is True, thus
        # they won't deselect the item the user selected
        self.rightClickMenuActive = False

        self.provider = ida.IDA()

        super(UI, self).__init__()


    def setupHotkeys(self):

        # thx peter v for CompileLine suggestion
        modulename = type(self).__module__

        # history hotkey
        history_hotkey = self.options['history_hotkey']
        self.provider.compile('static _keypress() { RunPythonStatement("toolbag.%s.addToHistory()");}' % modulename)
        self.provider.addHotkey(history_hotkey, "_keypress")

        # undo history add
        undo_history_hotkey = self.options['undo_history']
        self.provider.compile('static _undo_history() { RunPythonStatement("toolbag.%s.undoHistory()");}' % modulename)
        self.provider.addHotkey(undo_history_hotkey, "_undo_history")

        # marks
        create_mark_hotkey = self.options['create_mark_hotkey']
        self.provider.compile('static _create_mark() { RunPythonStatement("toolbag.%s.CreateMark()");}' % modulename)
        self.provider.addHotkey(create_mark_hotkey, "_create_mark")

        jump_mark_hotkey = self.options['jump_mark_hotkey']
        self.provider.compile('static _jump_mark() { RunPythonStatement("toolbag.%s.JumpMark()");}' % modulename)
        self.provider.addHotkey(jump_mark_hotkey, "_jump_mark")    

        # pathfinding
        self.provider.compile('static _path_start() { RunPythonStatement("toolbag.%s.PathStart()");}' % modulename)
        self.provider.addHotkey(self.options['path_start'], "_path_start")        

        self.provider.compile('static _path_end() { RunPythonStatement("toolbag.%s.PathEnd()");}' % modulename)
        self.provider.addHotkey(self.options['path_end'], "_path_end")  

        # adding edges
        self.provider.compile('static _edge_source() { RunPythonStatement("toolbag.%s.addEdgeSource()");}' % modulename)
        self.provider.addHotkey(self.options['add_edge_src'], "_edge_source")        
        self.provider.compile('static _edge_dest() { RunPythonStatement("toolbag.%s.addEdgeDest()");}' % modulename)
        self.provider.addHotkey(self.options['add_edge_dst'], "_edge_dest")

        # XXX: deprecated
        #idaapi.CompileLine('static _bbpath_start() { RunPythonStatement("toolbag.%s.BBPathStart()");}' % modulename)
        #idc.AddHotkey(self.options['bb_path_start'], "_bbpath_start")        

        #idaapi.CompileLine('static _bbpath_end() { RunPythonStatement("toolbag.%s.BBPathEnd()");}' % modulename)
        #idc.AddHotkey(self.options['bb_path_end'], "_bbpath_end")  


    # MakeComment hook
    def tbMakeComment(self):
        if self.options['dev_mode']:
            print "[D] tbMakeComment: printing stack:"
            traceback.print_stack()

        # grab the current EA
        ea = self.provider.currentEA()

        # retrieve our dictionary
        comment_dict = pickle.loads(self.fs.load("default.cmts"))

        # grab the comment
        text = self.provider.getComment(ea)

        # set 
        comment_dict[ea] = text

        # save it back to the FS
        self.fs.store("default.cmts", pickle.dumps(comment_dict))

        # refresh the FS tab
        self.refreshFilesystem()

        # refresh comments
        self.refreshCmts()

    # MakeFunction
    def tbMakeFunction(self):
        if self.options['dev_mode']:
            print "[D] tbMakeFunction: printing stack:"
            traceback.print_stack()
        self.master.add_func(self.provider.currentEA())
        self.reftree.add_func(self.provider.currentEA())
        #self.global_hook.reanalyze()


    # MakeRptCmt hook
    def tbMakeRptCmt(self):
        if self.options['dev_mode']:
            print "[D] tbMakeRptCmt: printing stack:"
            traceback.print_stack()

        # grab the current EA
        ea = self.provider.currentEA()

        # retrieve our dictionary
        rcomment_dict = pickle.loads(self.fs.load("default.rcmts"))

        # grab the rcomment 
        text = self.provider.getRptComment(ea)

        # set
        rcomment_dict[ea] = text

        # save it back to the FS
        self.fs.store("default.rcmts", pickle.dumps(rcomment_dict))

        # refresh the FS tab
        self.refreshFilesystem()

        # refresh comments
        self.refreshCmts()


    # MakeName hook
    def tbMakeName(self):
        if self.options['dev_mode']:
            print "[D] tbMakeName: printing stack:"
            traceback.print_stack()
        # XXX
        # this can be hit when stack args/vars, structs, enums are renamed
       
    def OnCreate(self, form):
        self.parent = self.FormToPySideWidget(form)
        self.new_windows = []
        self.dyn_imports = dict()

        self.edge_dest   = None
        self.edge_source = None

        # set up hotkeys
        self.setupHotkeys()

        # store initial comment/repeatable dictionaries, if they aren't present
        try:
            comment_dict = pickle.loads(self.fs.load("default.cmts"))
        except TypeError:
            comment_dict = {}

        self.fs.store("default.cmts", pickle.dumps(comment_dict))

        try:
            rcomment_dict = pickle.loads(self.fs.load("default.rcmts"))
        except TypeError:
            rcomment_dict = {}

        self.fs.store("default.rcmts", pickle.dumps(rcomment_dict))

        # store initial name dictionary, if it isn't present
        try:
            name_dict = pickle.loads(self.fs.load("default.names"))
        except:
            name_dict = {}
            self.fs.store("default.names", pickle.dumps(name_dict))

        self.PopulateForm()


    def createTabAndContainer(self, title, layout):
        if self.options['dev_mode']:
            print "[D] createTabAndContainer: printing stack:"
            traceback.print_stack()

        t = QtGui.QWidget()
        t.setWindowTitle(title)
        c = layout()
        t.setLayout(c)
        return (t, c)


    def initHistoryTree(self):
        if self.options['dev_mode']:
            print "[D] initHistoryTree: printing stack:"
            traceback.print_stack()

        history_obj      = QtGui.QTreeWidget()
        self.history_obj = history_obj
        history_obj.setHeaderLabels(("Name","Address"))
        history_obj.setColumnCount(2)
        history_obj.setColumnWidth(0, 300)
        history_obj.setColumnWidth(1, 40)
        history_obj.itemClicked.connect(self.historyClicked)

        class rightclicka(QtCore.QObject):
            def eventFilter(self, obj, event):
                if event.type() == QtCore.QEvent.Type.ContextMenu:

                    menu = QtGui.QMenu()

                    push_action     = menu.addAction("Push to peers")
                    query_action    = menu.addAction("Query DB")
                    remove_action   = menu.addAction("Remove Node")
                    strings_action  = menu.addAction("Gather Strings")

                    obj.connect(query_action, QtCore.SIGNAL("triggered()"), self.ui.queryGraph)
                    obj.connect(push_action, QtCore.SIGNAL("triggered()"), self.ui.invokeQueues)
                    obj.connect(remove_action, QtCore.SIGNAL("triggered()"), self.ui.removeNode)
                    obj.connect(strings_action, QtCore.SIGNAL("triggered()"), self.ui.gatherStrings)
                    
                    menu.popup(obj.mapToGlobal(event.pos()))
                    self.ui.rightClickMenuActive = True
                    menu.exec_()
                    self.ui.rightClickMenuActive = False
                    return True
                    
                return False

        eventFilter = rightclicka(history_obj)
        rightclicka.ui = self
        history_obj.installEventFilter(eventFilter)


    def initLocalCmts(self):
        if self.options['dev_mode']:
            print "[D] initLocalCmts: printing stack:"
            traceback.print_stack()

        local_cmts      = QtGui.QTreeWidget()
        self.local_cmts = local_cmts
        local_cmts.setHeaderLabels(("Description", "Location", "Address"))
        local_cmts.setColumnCount(3)
        local_cmts.setColumnWidth(0, 120)
        local_cmts.setColumnWidth(1, 100)
        local_cmts.setColumnWidth(2, 50)
        local_cmts.setSortingEnabled(True)
        local_cmts.itemClicked.connect(self.localCmtClicked)


        local_cmts_label      = QtGui.QLabel()
        self.local_cmts_label = local_cmts_label
        local_cmts_label.setText("Local comments:")

    def initLocalMarks(self):
        if self.options['dev_mode']:
            print "[D] initLocalMarks: printing stack:"
            traceback.print_stack()
            
        local_marks      = QtGui.QTreeWidget()
        self.local_marks = local_marks
        local_marks.setHeaderLabels(("Description", "Location", "Group", "Address"))
        local_marks.setColumnCount(4)
        local_marks.setColumnWidth(0, 120)
        local_marks.setColumnWidth(1, 100)
        local_marks.setColumnWidth(2, 50)
        local_marks.setColumnWidth(3, 20)
        local_marks.setSortingEnabled(True)
        local_marks.itemClicked.connect(self.localMarkClicked)

        # install the right-click context menu
        class rightclicka(QtCore.QObject):
            def eventFilter(self, obj, event):
                if event.type() == QtCore.QEvent.Type.ContextMenu:

                    menu = QtGui.QMenu()

                    delete_action = menu.addAction("Delete")
                    push_action   = menu.addAction("Push to peers")
                    
                    obj.connect(delete_action, QtCore.SIGNAL("triggered()"), self.ui.deleteLocalMark)
                    obj.connect(push_action, QtCore.SIGNAL("triggered()"), self.ui.pushMarksToPeers)
                    
                    menu.popup(obj.mapToGlobal(event.pos()))
                    self.ui.rightClickMenuActive = True
                    menu.exec_()
                    self.ui.rightClickMenuActive = False
                    return True
                    
                return False

        eventFilter = rightclicka(local_marks)
        rightclicka.ui = self
        local_marks.installEventFilter(eventFilter)


        local_marks_label      = QtGui.QLabel()
        self.local_marks_label = local_marks_label
        local_marks_label.setText("Local marks:")


    def initShowImports(self):
        if self.options['dev_mode']:
            print "[D] initShowImports: printing stack:"
            traceback.print_stack()
            
        self.show_imports = False
        import_calls      = QtGui.QTreeWidget()
        self.import_calls = import_calls
        import_calls.setHeaderLabels(("Import Name", "Caller", "Address"))
        import_calls.setColumnCount(3)
        import_calls.setSortingEnabled(True)
        import_calls.itemClicked.connect(self.importCallClicked)
        self.import_calls.setVisible(False)

        import_calls_label = QtGui.QLabel()
        import_calls_label.setText("")
        self.import_calls_label = import_calls_label


    def initShowStrings(self):
        if self.options['dev_mode']:
            print "[D] initShowStrings: printing stack:"
            traceback.print_stack()
            
        self.show_strings = False
        string_refs = QtGui.QTreeWidget()
        self.string_refs = string_refs
        string_refs.setHeaderLabels(("String", "Caller", "Address"))
        string_refs.setColumnCount(3)
        string_refs.setSortingEnabled(True)
        string_refs.itemClicked.connect(self.importCallClicked)
        string_refs.setVisible(False)

        string_refs_label = QtGui.QLabel()
        string_refs_label.setText("")
        self.string_refs_label = string_refs_label


    def initToolbarButtons(self, name, tooltip, callback):
        if self.options['dev_mode']:
            print "[D] initToolbarButtons: printing stack:"
            traceback.print_stack()
            

        obj = getattr(self, name)
        obj.setToolTip(tooltip)
        obj.clicked.connect(callback)
        return 


    def addItemsToContainer(self, container, items):
        if self.options['dev_mode']:
            print "[D] addItemsToContainer: printing stack:"
            traceback.print_stack()
            
        for i in items:
            container.addWidget(i)


    def initFileSystem(self):
        if self.options['dev_mode']:
            print "[D] initFileSystem: printing stack:"
            traceback.print_stack()
            
        fs_tree = QtGui.QTreeWidget()
        fs_tree.setHeaderLabels(("Filename", "Size", "ext"))
        fs_tree.setColumnCount(3)
        fs_tree.setColumnWidth(0, 200)
        fs_tree.setColumnWidth(1, 100)
        fs_tree.setColumnWidth(2, 20)

        # XXX: this has to be a custom sort, based on extension
        # or we can add an 'ext' column like i just did 'cause we're lazy
        fs_tree.setSortingEnabled(True)
        fs_tree.setSelectionMode(QtGui.QAbstractItemView.ExtendedSelection)


        class rightclicka(QtCore.QObject):
            def eventFilter(self, obj, event):
                if event.type() == QtCore.QEvent.Type.ContextMenu:

                    # i'm really trying hard not to re-organize this into a 
                    # more aesthetically pleasing cascade of code
                    menu = QtGui.QMenu()

                    load_action            = menu.addAction("Load in History")
                    merge_action           = menu.addAction("Merge Sessions")
                    export_action          = menu.addAction("Export")
                    delete_action          = menu.addAction("Delete")
                    add_file_action        = menu.addAction("Add File")
                    apply_action           = menu.addAction("Apply")
                    push_peers_action      = menu.addAction("Push to Peers")
                    save_to_retvals_action = menu.addAction("Save as variable...")

                    obj.connect(apply_action, QtCore.SIGNAL("triggered()"), self.ui.applyFile)
                    obj.connect(add_file_action, QtCore.SIGNAL("triggered()"), self.ui.addFile)
                    obj.connect(load_action, QtCore.SIGNAL("triggered()"), self.ui.loadSessFile)
                    obj.connect(export_action, QtCore.SIGNAL("triggered()"), self.ui.exportFile)
                    obj.connect(delete_action, QtCore.SIGNAL("triggered()"), self.ui.deleteFile)
                    obj.connect(merge_action, QtCore.SIGNAL("triggered()"), self.ui.mergeSessFiles)
                    obj.connect(push_peers_action, QtCore.SIGNAL("triggered()"), self.ui.pushPeers)
                    obj.connect(save_to_retvals_action, QtCore.SIGNAL("triggered()"), self.ui.saveToRetVals)
                    
                    menu.popup(obj.mapToGlobal(event.pos()))
                    self.ui.rightClickMenuActive = True
                    menu.exec_()
                    self.ui.rightClickMenuActive = False
                    return True
                    
                return False

        eventFilter = rightclicka(fs_tree)
        rightclicka.ui = self
        fs_tree.installEventFilter(eventFilter)

        self.fsTree = fs_tree
        self.refreshFilesystem()


    def initGlobalMarks(self):
        if self.options['dev_mode']:
            print "[D] initGlobalMarks: printing stack:"
            traceback.print_stack()
            
        mark_list = QtGui.QTreeWidget()
        mark_list.setHeaderLabels(("Description", "Location", "Group", "Address"))
        mark_list.setColumnCount(4)
        mark_list.setColumnWidth(0, 120)
        mark_list.setColumnWidth(1, 100)
        mark_list.setColumnWidth(2, 50)
        mark_list.setColumnWidth(3, 20)
        mark_list.setSortingEnabled(True)
        mark_list.itemClicked.connect(self.markClicked)

        # install the right-click context menu
        class rightclicka(QtCore.QObject):
            def eventFilter(self, obj, event):
                if event.type() == QtCore.QEvent.Type.ContextMenu:

                    menu = QtGui.QMenu()

                    delete_action = menu.addAction("Delete")
                    push_action   = menu.addAction("Push to peers")
                    
                    obj.connect(delete_action, QtCore.SIGNAL("triggered()"), self.ui.deleteGlobalMark)
                    obj.connect(push_action, QtCore.SIGNAL("triggered()"), self.ui.pushMarksToPeers)

                    menu.popup(obj.mapToGlobal(event.pos()))
                    self.ui.rightClickMenuActive = True
                    menu.exec_()
                    self.ui.rightClickMenuActive = False
                    return True
                    
                return False

        eventFilter = rightclicka(mark_list)
        rightclicka.ui = self
        mark_list.installEventFilter(eventFilter)

        self.markList = mark_list
        self.refreshMarks()


    def initUserScripts(self):
        if self.options['dev_mode']:
            print "[D] initUserScripts: printing stack:"
            traceback.print_stack()
            
        fileSystemModel = QtGui.QFileSystemModel()
        fileSystemModel.setFilter(QtCore.QDir.Files)
        fileSystemModel.setNameFilters(["*.py"])
        fileSystemModel.setNameFilterDisables(False)
        
        rootPath = self.options['user_scripts_dir']
        
        fileSystemModel.setRootPath(rootPath)
        view = QtGui.QListView()
        view.setModel(fileSystemModel)
        view.setRootIndex(fileSystemModel.index(rootPath))
        view.activated.connect(self.userScriptsActivated)
        self.userScripts      = view
        self.userScriptsModel = fileSystemModel

        self.user_scripts_label = QtGui.QLabel()
        self.user_scripts_label.setText("User Scripts\n--\nDouble click to execute:")

        fileSystemModel2 = QtGui.QFileSystemModel()
        fileSystemModel2.setFilter(QtCore.QDir.Files)
        fileSystemModel2.setNameFilters(["*.py"])
        fileSystemModel2.setNameFilterDisables(False)
        rootPath = self.options['vtrace_scripts_dir']
        
        fileSystemModel2.setRootPath(rootPath)
        view = QtGui.QListView()
        view.setModel(fileSystemModel2)
        view.setRootIndex(fileSystemModel2.index(rootPath))
        #view.activated.connect(self.vtraceScriptsActivated)
        self.vtraceScripts      = view
        self.vtraceScriptsModel = fileSystemModel2

        self.vtrace_scripts_label = QtGui.QLabel()
        self.vtrace_scripts_label.setText("VTrace scripts\n--\nRight-click to invoke:")


        # right clicker for vtrace scripts
        class rightclicka_vtrace(QtCore.QObject):
            def eventFilter(self, obj, event):
                if event.type() == QtCore.QEvent.Type.ContextMenu:

                    menu = QtGui.QMenu()

                    edit_action    = menu.addAction("Edit...")
                    prep_action = menu.addAction("Prepare ...")
                    run_action    = menu.addAction("Run on Agent ...")
                    process_action = menu.addAction("Process Results...")

                    obj.connect(edit_action, QtCore.SIGNAL("triggered()"), self.ui.editVtraceScript)
                    obj.connect(run_action, QtCore.SIGNAL("triggered()"), self.ui.runVtraceScript)
                    obj.connect(process_action, QtCore.SIGNAL("triggered()"), self.ui.processVTraceScript)
                    obj.connect(prep_action, QtCore.SIGNAL("triggered()"), self.ui.prepVtraceScript)
                    
                    menu.popup(obj.mapToGlobal(event.pos()))
                    self.ui.rightClickMenuActive = True
                    menu.exec_()
                    self.ui.rightClickMenuActive = False
                    return True
                    
                return False

        eventFilter = rightclicka_vtrace(self.vtraceScripts)
        rightclicka_vtrace.ui = self
        self.vtraceScripts.installEventFilter(eventFilter)

        class rightclicka_user(QtCore.QObject):
            def eventFilter(self, obj, event):
                if event.type() == QtCore.QEvent.Type.ContextMenu:

                    menu = QtGui.QMenu()
                    edit_action = menu.addAction("Edit...")

                    obj.connect(edit_action, QtCore.SIGNAL("triggered()"), self.ui.editUserScript)

                    menu.popup(obj.mapToGlobal(event.pos()))
                    menu.exec_()
                    return True
                    
                return False

        eventFilter = rightclicka_user(self.userScripts)
        rightclicka_user.ui = self
        self.userScripts.installEventFilter(eventFilter)


        self.refreshScripts()
        self.refreshVTraceScripts()


    def initPathfinding(self):
        if self.options['dev_mode']:
            print "[D] initPathfinding: printing stack:"
            traceback.print_stack()

        pathfinding_group     = QtGui.QWidget()
        pathfinding_container = QtGui.QVBoxLayout()
        pathfinding_group.setLayout(pathfinding_container)

        function_group     = QtGui.QWidget()
        function_container = QtGui.QVBoxLayout()
        function_group.setLayout(function_container)

        function_label = QtGui.QLabel()
        function_label.setText("Function:")

        f_start_end_container = QtGui.QVBoxLayout()
        f_start_end_group     = QtGui.QWidget()
        f_start_end_group.setLayout(f_start_end_container)
        
        path_start     = QtGui.QLabel() 
        self.pathStart = path_start
        path_start.setText("Start address:")

        path_end     = QtGui.QLabel()
        self.pathEnd = path_end
        path_end.setText("End address:")

        button_container = QtGui.QHBoxLayout()
        button_group     = QtGui.QWidget()
        button_group.setLayout(button_container)

        plot_fpath = QtGui.QPushButton("Plot Function Path")
        plot_fpath.clicked.connect(self.plot_path)

        button_container.addStretch(1)
        button_container.addWidget(plot_fpath)
        button_container.addStretch(1)

        #f_start_end_container.addStretch(1)
        f_start_end_container.addWidget(path_start)
        #f_start_end_container.addStretch(1)
        f_start_end_container.addWidget(path_end)
        #f_start_end_container.addStretch(1)

        pathfinding_container.addWidget(f_start_end_group)
        pathfinding_container.addWidget(button_group)

        bb_group     = QtGui.QWidget()
        bb_container = QtGui.QVBoxLayout()
        bb_group.setLayout(bb_container)

        b_start_end_container = QtGui.QVBoxLayout()
        b_start_end_group     = QtGui.QWidget()
        b_start_end_group.setLayout(b_start_end_container)


        button2_container = QtGui.QHBoxLayout()
        button2_group     = QtGui.QWidget()
        button2_group.setLayout(button2_container)

        plot_bpath = QtGui.QPushButton("Plot Basic Block Path to Current EA")
        plot_bpath.clicked.connect(self.plot_bb_path)

        button2_container.addStretch(1)
        button2_container.addWidget(plot_bpath)
        button2_container.addStretch(1)

        pathfinding_container.addWidget(b_start_end_group)
        pathfinding_container.addWidget(button2_group)

        self.pathfinding_group = pathfinding_group
    

    def initOptions(self):
        if self.options['dev_mode']:
            print "[D] initOptions: printing stack:"
            traceback.print_stack()
            
        options_group = QtGui.QWidget()
        options_container = QtGui.QVBoxLayout()
        options_group.setLayout(options_container)

        label = QtGui.QLabel()
        label.setText("Super ghetto way to edit your options on the fly\n--\n(apologies for formatting)\n")

        # this is so ghetto
        output = "options = {\n"
        for k, v in self.options.iteritems():

            if type(v) == type(True):
                if v:
                    output += "\t'%s'\t:\tTrue,\n" % k
                else:
                    output += "\t'%s'\t:\tFalse,\n" % k

            elif type(v) == type(""):
                output += "\t'%s'\t:\t'%s',\n" % (k, v)                

            elif type(v) == type(0):
                output += "\t'%s'\t:\t%d,\n" % (k, v)

            elif type(v) == type([]):
                output += "\t'%s'\t:\t%s\n," % (k,v)

        output += "}\n"

        wow = QtGui.QTextEdit()
        wow.setText(output)

        self.dynamicOptions = wow

        apply_button = QtGui.QPushButton()
        apply_button.setText("Apply")
        apply_button.clicked.connect(self.applyOptions)

        options_container.addWidget(label) 
        options_container.addWidget(wow) 
        options_container.addWidget(apply_button) 
        self.options_group = options_group


    def initQueues(self):
        if self.options['dev_mode']:
            print "[D] initQueues: printing stack:"
            traceback.print_stack()
            
        host_group     = QtGui.QWidget()
        host_container = QtGui.QHBoxLayout()
        host_group.setLayout(host_container)

        port_group     = QtGui.QWidget()
        port_container = QtGui.QHBoxLayout()
        port_group.setLayout(port_container)

        key_group     = QtGui.QWidget()
        key_container = QtGui.QHBoxLayout()
        key_group.setLayout(key_container)


        add_item_group     = QtGui.QWidget()
        add_item_container = QtGui.QHBoxLayout()
        add_item_group.setLayout(add_item_container)

        radio_group     = QtGui.QWidget()
        radio_container = QtGui.QVBoxLayout()
        radio_group.setLayout(radio_container)


        # host
        host = QtGui.QLabel()
        host.setText("Host:")
        host_container.addWidget(host)

        host_input        = QtGui.QLineEdit()
        self.queueHostObj = host_input
        #if self.options.has_key('host'):
        #    self.queueHost = self.options['server_host']
        #    server_host_input.setPlaceholderText(self.options['server_host'])
        #else:
        host_input.setPlaceholderText("<enter ip or hostname>")
        host_container.addWidget(host_input)

        # port
        port = QtGui.QLabel()
        port.setText("Port:")
        port_container.addWidget(port)

        port_input        = QtGui.QLineEdit()
        self.queuePortObj = port_input
        port_input.setPlaceholderText("<enter port number>")
        port_container.addWidget(port_input)

        # key
        key = QtGui.QLabel()
        key.setText("Key:")
        key_container.addWidget(key)

        key_input        = QtGui.QLineEdit()
        self.queueKeyObj = key_input
        key_input.setPlaceholderText("<enter key>")
        key_container.addWidget(key_input)

        # add button and radio buttons
        add_queue = QtGui.QPushButton()
        add_queue.setText("Add")
        add_queue.clicked.connect(self.addQueue)
        add_item_container.addWidget(add_queue)

        peerRadio      = QtGui.QRadioButton(radio_group)
        self.peerRadio = peerRadio
        peerRadio.setText("Peer")

        serverRadio      = QtGui.QRadioButton(radio_group)
        self.serverRadio = serverRadio
        serverRadio.setText("Server")
        
        
        agentRadio      = QtGui.QRadioButton(radio_group)
        self.agentRadio = agentRadio
        agentRadio.setText("Agent")
        

        self.queueRadioGroup = radio_group

        add_item_container.addWidget(serverRadio)
        add_item_container.addWidget(peerRadio)
        add_item_container.addWidget(agentRadio)

        # input group
        queue_input_group = QtGui.QWidget()
        input_container   = QtGui.QVBoxLayout()
        queue_input_group.setLayout(input_container)

        input_container.addWidget(host_group)
        input_container.addWidget(port_group)
        input_container.addWidget(key_group)
        input_container.addWidget(add_item_group, alignment=QtCore.Qt.AlignLeft)
        
        self.queueInput = queue_input_group

        # Queue List
        queue_list = QtGui.QTreeWidget()
        queue_list.setHeaderLabels(("Host", "", "Type", ""))
        queue_list.setColumnCount(4)
        self.queueList = queue_list
        #path_list.itemClicked.connect(self.pathClicked)


        # right click context
        class rightclicka(QtCore.QObject):
            def eventFilter(self, obj, event):
                if event.type() == QtCore.QEvent.Type.ContextMenu:

                    menu = QtGui.QMenu()

                    store_action  = menu.addAction("Store...")
                    reject_action = menu.addAction("Reject")
                    delete_action = menu.addAction("Delete")

                    obj.connect(delete_action, QtCore.SIGNAL("triggered()"), self.ui.deleteQueue)
                    obj.connect(store_action, QtCore.SIGNAL("triggered()"), self.ui.saveQueueData)
                    obj.connect(reject_action, QtCore.SIGNAL("triggered()"), self.ui.rejectQueueData)

                    menu.popup(obj.mapToGlobal(event.pos()))
                    self.ui.rightClickMenuActive = True
                    menu.exec_()
                    self.ui.rightClickMenuActive = False
                    return True
                    
                return False

        eventFilter = rightclicka(queue_list)
        rightclicka.ui = self
        queue_list.installEventFilter(eventFilter)

        self.refreshQueueList()


    def PopulateForm(self):
        if self.options['dev_mode']:
            print "[D] PopulateForm: printing stack:"
            traceback.print_stack()
            

        layout = QtGui.QVBoxLayout()

        tabs = QtGui.QTabWidget()
        tabs.setMovable(True)
        self.tabs = tabs

        # Tab #1 - History Tree
        tab1, tab1_container = self.createTabAndContainer("History", QtGui.QVBoxLayout)
        self.historyTab = tab1

        # Create history tree
        self.initHistoryTree()

        #if self.options['localview'] == 'marks':
        # Create local marks
        self.initLocalMarks()
        #else:
        # Create local comments
        self.initLocalCmts()

        # Create show imports view
        self.initShowImports()

        # Create the show strings view
        self.initShowStrings()

        stupid = QtGui.QWidget()
        stupid_container = QtGui.QVBoxLayout()
        #stupid_container.setSizeConstraint(QtGui.QLayout.SetFixedSize)
        stupid_container.setSpacing(0)
        stupid.setLayout(stupid_container)
        history_toolbar = QtGui.QToolBar()
        rsrc_dir = self.options['ida_user_dir'] + os.sep + "rsrc"
        
        save_icon = QtGui.QIcon(rsrc_dir + os.sep + "save.png")
        clear_icon = QtGui.QIcon(rsrc_dir + os.sep + "clear.png")
        import_icon = QtGui.QIcon(rsrc_dir + os.sep + "imports.png")
        strings_icon = QtGui.QIcon(rsrc_dir + os.sep + "strings.png")
        add_edge_icon = QtGui.QIcon(rsrc_dir + os.sep + "addedge.png")
        query_db_icon = QtGui.QIcon(rsrc_dir + os.sep + "querydb.png")
        push_peers_icon = QtGui.QIcon(rsrc_dir + os.sep + "pushpeers.png")
        
        self.save_button = QtGui.QToolButton()
        self.save_button.setIcon(save_icon)

        self.clear_button = QtGui.QToolButton()
        self.clear_button.setIcon(clear_icon)
        
        self.show_imports_button = QtGui.QToolButton()
        self.show_imports_button.setIcon(import_icon)
        
        self.show_strings_button = QtGui.QToolButton()
        self.show_strings_button.setIcon(strings_icon)
        
        self.add_edge_button = QtGui.QToolButton()
        self.add_edge_button.setIcon(add_edge_icon)

        self.query_db_button = QtGui.QToolButton()
        self.query_db_button.setIcon(query_db_icon)

        self.push_peers_button = QtGui.QToolButton()
        self.push_peers_button.setIcon(push_peers_icon)
        
        history_toolbar.addWidget(self.save_button)
        history_toolbar.addWidget(self.clear_button)
        history_toolbar.addWidget(self.show_imports_button)
        history_toolbar.addWidget(self.show_strings_button)
        history_toolbar.addWidget(self.add_edge_button)
        history_toolbar.addWidget(self.query_db_button)
        history_toolbar.addWidget(self.push_peers_button)

        history_toolbar.setIconSize(QtCore.QSize(18, 18))

        stupid_container.addWidget(history_toolbar)
        tab1_container.addWidget(stupid)
        
        history_buttons = [ \
            ("clear_button", "Clear the current history view", self.clearHistory),
            ("save_button", "Save current history as a .sess file in the Filesystem", self.saveHistory),
            ("show_imports_button", "Toggle the display of the calls to imported funtions pane", self.importToggle),
            ("show_strings_button", "Toggle the display of the strings referenced pane", self.stringsToggle),
            ("add_edge_button", "Manually add edges to the ToolBag database", self.addEdge),
            ("query_db_button", "Perform a custom query against the Toolbag database", self.queryGraph),
            ("push_peers_button", "Push the current history tree to registered peers", self.pushPeers)
        ]
        for b in history_buttons:
            self.initToolbarButtons(b[0], b[1], b[2])

        stupid2 = QtGui.QWidget()
        stupid2_container = QtGui.QVBoxLayout()
        #stupid2_container.setSizeConstraint(QtGui.QLayout.SetFixedSize)
        stupid2_container.setSpacing(0)
        stupid2.setLayout(stupid2_container)

        if self.options['localview'] == 'marks':
            local_marks_toolbar = QtGui.QToolBar()
        
            delete_local_mark_icon = QtGui.QIcon(rsrc_dir + os.sep + "clear.png")
        
            self.delete_local_mark_button = QtGui.QToolButton()
            self.delete_local_mark_button.setIcon(delete_local_mark_icon)
        
            local_marks_toolbar.addWidget(self.delete_local_mark_button)

            local_marks_toolbar.setIconSize(QtCore.QSize(18, 18))

            stupid2_container.addWidget(local_marks_toolbar)
        
            local_mark_buttons = [ \
                ("delete_local_mark_button", "Delete the currently selected mark", self.deleteLocalMark)
            ]
            for b in local_mark_buttons:
                self.initToolbarButtons(b[0], b[1], b[2])
        else:
            # no toolbar
            pass

        split_thing = QtGui.QWidget()
        split_thing_container = QtGui.QVBoxLayout()
        split_thing.setLayout(split_thing_container)

        splitter = QtGui.QSplitter()
        splitter.setOrientation(QtCore.Qt.Vertical)
        splitter.addWidget(self.history_obj)
        splitter.addWidget(stupid2)

        if self.options['localview'] == 'marks':
            self.localview = self.local_marks
            splitter.addWidget(self.local_marks_label)
            splitter.addWidget(self.local_marks)
        else:
            self.localview = self.local_cmts
            splitter.addWidget(self.local_cmts_label)
            splitter.addWidget(self.local_cmts)

        split_thing_container.addWidget(splitter)

        # add stuff to tab1
        tab1_items = [ \
            splitter,
            self.import_calls_label,
            self.import_calls,
            self.string_refs_label,
            self.string_refs
        ]

        self.addItemsToContainer(tab1_container, tab1_items)

        # Tab #2 - File System View
        tab2, tab2_container = self.createTabAndContainer("File System", QtGui.QVBoxLayout)
        self.fsTab = tab2

        # Create file system widget
        self.initFileSystem()
        
        stupid = QtGui.QWidget()
        stupid_container = QtGui.QVBoxLayout()
        #stupid_container.setSizeConstraint(QtGui.QLayout.SetFixedSize)
        stupid_container.setSpacing(0)
        stupid.setLayout(stupid_container)
        filesystem_toolbar = QtGui.QToolBar()
        
        addfile_icon = QtGui.QIcon(rsrc_dir + os.sep + "addfile.png")
        removefile_icon = QtGui.QIcon(rsrc_dir + os.sep + "removefile.png")
        mergefile_icon = QtGui.QIcon(rsrc_dir + os.sep + "mergefile.png")
        exportfile_icon = QtGui.QIcon(rsrc_dir + os.sep + "exportfile.png")
        loadinhistory_icon = QtGui.QIcon(rsrc_dir + os.sep + "loadinhistory.png")
        apply_icon = QtGui.QIcon(rsrc_dir + os.sep + "apply.png")
        saveasvar_icon = QtGui.QIcon(rsrc_dir + os.sep + "save.png")
        
        
        self.addfile_button = QtGui.QToolButton()
        self.addfile_button.setIcon(addfile_icon)

        self.removefile_button = QtGui.QToolButton()
        self.removefile_button.setIcon(removefile_icon)

        self.mergefile_button = QtGui.QToolButton()
        self.mergefile_button.setIcon(mergefile_icon)

        self.exportfile_button = QtGui.QToolButton()
        self.exportfile_button.setIcon(exportfile_icon)

        self.loadinhistory_button = QtGui.QToolButton()
        self.loadinhistory_button.setIcon(loadinhistory_icon)

        self.apply_button = QtGui.QToolButton()
        self.apply_button.setIcon(apply_icon)

        self.saveasvar_button = QtGui.QToolButton()
        self.saveasvar_button.setIcon(saveasvar_icon)
        
        filesystem_toolbar.addWidget(self.addfile_button)
        filesystem_toolbar.addWidget(self.removefile_button)
        filesystem_toolbar.addWidget(self.exportfile_button)
        filesystem_toolbar.addWidget(self.mergefile_button)
        filesystem_toolbar.addWidget(self.loadinhistory_button)
        filesystem_toolbar.addWidget(self.apply_button)
        filesystem_toolbar.addWidget(self.saveasvar_button)


        filesystem_toolbar.setIconSize(QtCore.QSize(18, 18))

        stupid_container.addWidget(filesystem_toolbar)
        tab2_container.addWidget(stupid)
        
        filesystem_buttons = [ \
            ("addfile_button", "Add a file from the host filesystem to the pseudo filesystem", self.addFile),
            ("removefile_button", "Delete the currently selected file", self.deleteFile),
            ("exportfile_button", "Exports a file from the pseudo filesystem to the host filesystem", self.exportFile),
            ("mergefile_button", "Merge two .sess files and load them in the History view", self.mergeSessFiles),
            ("loadinhistory_button", "Load the currently selected .sess file in the History view", self.loadSessFile),
            ("apply_button", "Applies the currently selected (r)comments, marks, or names", self.applyFile),
            ("saveasvar_button", "Saves the currently selected item as a variable for programmatic access", self.saveToRetVals)
        ]
        for b in filesystem_buttons:
            self.initToolbarButtons(b[0], b[1], b[2])

        self.addItemsToContainer(tab2_container, [self.fsTree])
 
        # Tab #3 - Marks
        tab3, tab3_container = self.createTabAndContainer("Global Marks", QtGui.QVBoxLayout)
        self.markTab = tab3        

        stupid3 = QtGui.QWidget()
        stupid3_container = QtGui.QVBoxLayout()
        #stupid_container.setSizeConstraint(QtGui.QLayout.SetFixedSize)
        stupid3_container.setSpacing(0)
        stupid3.setLayout(stupid3_container)
        global_marks_toolbar = QtGui.QToolBar()
        
        delete_global_mark_icon = QtGui.QIcon(rsrc_dir + os.sep + "clear.png")
        
        self.delete_global_mark_button = QtGui.QToolButton()
        self.delete_global_mark_button.setIcon(delete_global_mark_icon)

        global_marks_toolbar.addWidget(self.delete_global_mark_button)

        global_marks_toolbar.setIconSize(QtCore.QSize(18, 18))

        stupid3_container.addWidget(global_marks_toolbar)
        
        
        global_marks_buttons = [ \
            ("delete_global_mark_button", "Deletes the currently selected mark", self.deleteGlobalMark)
        ]

        for b in global_marks_buttons:
            self.initToolbarButtons(b[0], b[1], b[2])

        # Create global mark widget
        self.initGlobalMarks()

        self.addItemsToContainer(tab3_container, [stupid3, self.markList])
     
        # Tab #4 - Scripts
        tab4, tab4_container = self.createTabAndContainer("Scripts", QtGui.QVBoxLayout)
        self.userScriptsTab = tab4

        # Create user scripts widget
        self.initUserScripts()
     
        self.addItemsToContainer(tab4_container, [self.user_scripts_label, self.userScripts, self.vtrace_scripts_label, self.vtraceScripts])

        # Tab #5 - Pathfinding
        tab5, tab5_container = self.createTabAndContainer("Pathfinding", QtGui.QVBoxLayout)
        self.pathFindingTab = tab5

        # create pathfinding widget
        self.initPathfinding()

        self.addItemsToContainer(tab5_container, [self.pathfinding_group])

        # Tab #6 - Queues
        tab6, tab6_container = self.createTabAndContainer("Queues", QtGui.QVBoxLayout)
        self.queueTab = tab6

        self.initQueues()

        # XXX
        tab6_container.addWidget(self.queueInput)
        tab6_container.addWidget(self.queueList)

        # Tab #7 - Options
        tab7, tab7_container = self.createTabAndContainer("Options", QtGui.QVBoxLayout)
        self.optionsTab = tab7
        self.initOptions()
        self.addItemsToContainer(tab7_container, [self.options_group])

        mainMenu = QtGui.QMenuBar()

        view_menu = QtGui.QMenu("View")
        mainMenu.addMenu(view_menu)
        self.view_menu = view_menu

        #options_menu = QtGui.QMenu("Options")
        #mainMenu.addMenu(options_menu)

        res = view_menu.addAction("Scripts", self.toggleUserScriptsTab)
        res.setCheckable(True)
        if "Scripts" in self.options['enabled_tabs']:
            res.setChecked(True)
            tabs.addTab(tab4, "Scripts")
        else:
             res.setChecked(False)

        res = view_menu.addAction("Pathfinding", self.togglePathfindingTab)
        res.setCheckable(True)
        if "Pathfinding" in self.options['enabled_tabs']:
            tabs.addTab(tab5, "Pathfinding")
            res.setChecked(True)
        else:
            res.setChecked(False)

        res = view_menu.addAction("Queues", self.toggleQueueTab)
        res.setCheckable(True)
        if "Queues" in self.options['enabled_tabs']:
            tabs.addTab(tab6, "Queues")
            res.setChecked(True)
        else:
            res.setChecked(False)

        res = view_menu.addAction("Options", self.toggleOptionsTab)
        res.setCheckable(True)
        if "Options" in self.options['enabled_tabs']:
            tabs.addTab(tab7, "Options")
            res.setChecked(True)
        else:
            res.setChecked(False)

        res = view_menu.addAction("File System", self.toggleFileSystemTab)
        res.setCheckable(True)
        if "File System" in self.options['enabled_tabs']:
            tabs.addTab(tab2, "File System")
            res.setChecked(True)
        else:
            res.setChecked(False)

        # add ability to launch function analysis
        res = view_menu.addAction("Function Analysis", self.launch_Analysis)

        # add the ability to launch the splash screen
        res = view_menu.addAction("Welcome Screen", self.viewSplash)

        # enabled, all the time
        tabs.addTab(tab1, "History")
        tabs.addTab(tab3, "Global Marks")
        
        # refresh marks every second or so
        self.timerthing()

        # load the default session if its available
        try:
            self.loadSessFile(default=True)
        except Exception as detail:
            print "[!] Failed to load default session: %s" % detail
            self.clearHistory()

        # http://www.rainbowpuke.com/pics/newpukes/nickburns-rainbowpuke.gif
        bgbrush = QtGui.QBrush(QtGui.QColor(self.options['background_color']))
        palette = QtGui.QPalette()

        for w in [self.history_obj, self.fsTree, self.markList, self.localview, self.import_calls, self.string_refs]:
            v = w.viewport()
            palette.setBrush(v.backgroundRole(), bgbrush)
            v.setPalette(palette)

        layout.addWidget(mainMenu)

        layout.addWidget(tabs)

        self.parent.setLayout(layout)

        class MyUiHook(self.provider.UI_Hooks):
            def __init__(self, ui_obj):
                self.ui_obj = ui_obj
                self.ui_obj.provider.UI_Hooks.__init__(self)
                self.cmdname = "<no command>"
                self.handlers = {}

            def preprocess(self, name):
                #print("IDA preprocessing command: %s" % name)
                self.cmdname = name
                return 0

            def postprocess(self):
                #print("IDA finished processing command: %s" % self.cmdname)
                try:
                    #print "[*] Trying to call handler for %s" % self.cmdname
                    self.handlers[self.cmdname]()
                except KeyError:
                    pass
                return 0

            # slick like astro 
            def register_handler(self, action, func):
                self.handlers[action] = func
                return 0

            #def term(self):
            #    self.unhook()

        uihook = MyUiHook(self)
        uihook.hook()
        self.ui_hook = uihook

        atexit.register(uihook.unhook)

        # ui hooks
        self.ui_hook.register_handler("MakeName", self.tbMakeName)
        self.ui_hook.register_handler("MakeComment", self.tbMakeComment)
        self.ui_hook.register_handler("MakeRptCmt", self.tbMakeRptCmt)
        self.ui_hook.register_handler("MakeFunction", self.tbMakeFunction)



    def importToggle(self):
        if self.options['dev_mode']:
            print "[D] importToggle: printing stack:"
            traceback.print_stack()
            
        if self.show_imports != True:
            self.show_imports = True
            self.show_imports_button.setText("Hide Import Calls")
            self.import_calls_label.setText("Calls to imported functions:")
        else:
            self.show_imports_button.setText("Show Import Calls")
            self.show_imports = False
            self.import_calls_label.setText("")

        self.refreshImports()

    def stringsToggle(self):
        if self.options['dev_mode']:
            print "[D] stringsToggle: printing stack:"
            traceback.print_stack()
            
        if self.show_strings != True:
            self.show_strings = True
            self.show_strings_button.setText("Hide Strings")
            self.string_refs_label.setText("String references:")
        else:
            self.show_strings_button.setText("Show String References")
            self.show_strings = False
            self.string_refs_label.setText("")

        self.refreshStrings()


    def createChildrenItems(self, tree, parentWidget):
        if self.options['dev_mode']:
            print "[D] createChildrenItems: printing stack:"
            traceback.print_stack()
            
        root       = tree[0]        
        children   = tree[1]
        rootWidget = QtGui.QTreeWidgetItem(parentWidget)
       
        name = self.provider.demangleName(self.provider.getName(root))
        if name == None:
            name = self.provider.getName(root)

        font = QtGui.QFont(self.options['font_name'], int(self.options['font_size']))

        rootWidget.setFont(0, font)
        rootWidget.setFont(1, font)

        rootWidget.setText(0, name)

        if self.options['architecture'] == "32":
            rootWidget.setText(1, "0x%08x" % root)
        else:
            rootWidget.setText(1, "0x%016x" % root)
        rootWidget.setExpanded(True)

        bgbrush = QtGui.QBrush(QtGui.QColor(self.options['background_color']))
        fgbrush = QtGui.QBrush(QtGui.QColor(self.options['font_color']))

        rootWidget.setForeground(0, fgbrush)
        rootWidget.setForeground(1, fgbrush)
        rootWidget.setBackground(0, bgbrush)
        rootWidget.setBackground(1, bgbrush)
        
        for child in children:
            self.createChildrenItems(child, rootWidget)


    def refreshQueueList(self):
         pass

    def refreshVTraceScripts(self):
        pass

    def refreshScripts(self):
        pass


    def prepVtraceScript(self):
        if self.options['dev_mode']:
            print "[D] prepVtraceScript: printing stack:"
            traceback.print_stack()
            
        #FIXME add a check to ensure agent is present
        #
        try:
            selected = self.vtraceScripts.currentIndex().data()
        except:
            print "[!] No file selected"
            self.rightClickMenuActive = False
            return 

        sys.path.append(self.options['vtrace_scripts_dir'])
        
        fname = selected
        modulename = fname.split(".py")[0]

        #FIXME check to see if myhost exists, complain if it doesnt
        agent = self.myhost.agent

        try:
            _script = __import__(modulename)
        except Exception as detail:

            print detail
            self.rightClickMenuActive = False
            return

        print "[*] Invoking %s.ToolbagTask.prep()" % (modulename)
        agent.toolbagTask = _script.ToolbagTask(fname, self.myhost.agentData, self.myhost.serverData)

        # 'self' is the ui_obj, used by prep()
        agent.toolbagTask.prep(self)
        self.rightClickMenuActive = False
        return

    def runVtraceScript(self):
        self.myhost.agent.toolbagTask.run(self)

    def processVTraceScript(self):
        self.myhost.agent.toolbagTask.process(self)

    def highlightAddressList(self, addresses, color=0xFF):
        for addr in addresses:
            self.provider.setColor(addr, color)
        
    def editUserScript(self):
        if self.options['dev_mode']:
            print "[D] editUserScript: printing stack:"
            traceback.print_stack()
            
        try:
            selected = self.userScripts.currentIndex().data()
            edit_me  = self.options['user_scripts_dir'] + os.sep + selected
        except Exception as detail:
            if selected != None:
                print "[!] No file selected", detail
                self.rightClickMenuActive = False
                return 

        print "[*] Running user's editor on %s" % selected

        # lolololz
        subprocess.call([self.options['editor'], edit_me])

        self.rightClickMenuActive = False

    def editVtraceScript(self):
        if self.options['dev_mode']:
            print "[D] editVtraceScript: printing stack:"
            traceback.print_stack()
            
        try:
            selected = self.vtraceScripts.currentIndex().data()
            edit_me  = self.options['vtrace_scripts_dir'] + os.sep + selected
        except Exception as detail:
            if selected != None:
                print "[!] No file selected", detail
                self.rightClickMenuActive = False
                return 

        
        print "[*] Running user's editor on %s" % selected

        # lolololz
        subprocess.call([self.options['editor'], edit_me])

        self.rightClickMenuActive = False


    def userScriptsActivated(self, index):
        if self.options['dev_mode']:
            print "[D] userScriptsActivated: printing stack:"
            traceback.print_stack()
            
        fileInfo = self.userScriptsModel.fileInfo(index)
        abs_path = fileInfo.absoluteFilePath()
        module   = os.path.split(abs_path)[1]
        module   = os.path.splitext(module)[0]

        sys.path.append(os.path.split(abs_path)[0])

        # sweet, i know.
        if module:

            # check for lack of imports
            if len(self.dyn_imports) == 0:
                
                # try importing the .py
                try:
                    x = __import__(module)
                    try:
                        setattr(x, "ui_obj", self)
                        x.init()
                    except Exception as detail:
                        print detail
                        pass
                    
                except Exception as detail:
                    print detail
                    return

                # update our dict
                self.dyn_imports[module] = x

            else:
                # if it is in our namespace already, reload it
                if self.dyn_imports.has_key(module):
                    x = reload(self.dyn_imports[module])
                    try:
                        setattr(x, "ui_obj", self)
                        x.init()
                    except Exception as detail:
                        print detail
                        pass
                else:
                    # otherwise, import it and update dict
                    try:
                        x = __import__(module)

                        try:
                            setattr(x, "ui_obj", self)
                            x.init()
                        except Exception as detail:
                            print detail
                            pass

                        self.dyn_imports[module] = x
                    except Exception as detail:
                        print detail

        return


    def vtraceScriptsActivated(self, index):
        if self.options['dev_mode']:
            print "[D] vtraceScriptsActivated: printing stack:"
            traceback.print_stack()
            
        fileInfo = self.vtraceScriptsModel.fileInfo(index)
        abs_path = fileInfo.absoluteFilePath()
        module   = os.path.split(abs_path)[1]
        module   = os.path.splitext(module)[0]

        sys.path.append(os.path.split(abs_path)[0])

        # sweet, i know.
        if module:

            # check for lack of imports
            if len(self.dyn_imports) == 0:
                
                # try importing the .py
                try:
                    x = __import__(module)
                except Exception as detail:
                    print detail
                    return

                # update our dict
                self.dyn_imports[module] = x

            else:
                # if it is in our namespace already, reload it
                if self.dyn_imports.has_key(module):
                    reload(self.dyn_imports[module])
                else:
                    # otherwise, import it and update dict
                    try:
                        x = __import__(module)
                        self.dyn_imports[module] = x
                    except Exception as detail:
                        print detail
        return


    def undoHistory(self):
        if self.options['dev_mode']:
            print "[D] undoHistory: printing stack:"
            traceback.print_stack()
            
        if self.reftree == None:
            return

        self.reftree.del_func(self.last_history_added)
        self.history_obj.clear()
        self.addToHistory(add=False)


    def addToHistory(self, add=True, userEA=False):
        if self.options['dev_mode']:
            print "[D] addToHistory: printing stack:"
            traceback.print_stack()
            
        treewidget = self.history_obj

        if userEA == False:
            ea = self.provider.currentEA()
        else:
            ea = userEA

        try:
            top = function.top(ea)
        except ValueError:
            # likely an import
            top = ea

        if self.reftree == None:
            if self.options['dev_mode']:
                print 'DEBUG> self.reftree is None, making a new one'
            self.reftree = RefTree.RefTree(masterGraph=self.master)

        is_import = False
        if not database.isCode(ea):
            # check for import!
            if self.provider.segName(ea) != ".idata":
                print "[!] Attempted to add an EA that wasn't code."
                add = False
            else:
                is_import = True

        if add != False:
            treewidget.clear()            
            if self.options['coloring_enabled'] == True:    

                if is_import:
                    self.provider.setColor(ea, self.options['history_color'])

                else:
                    block = self.provider.basicBlockBoundaries(ea)

                    for i in self.provider.iterInstructions(block[0], block[1]):
                        self.provider.setColor(i, self.options['history_color'])
            
            if self.options['dev_mode']:
                print "[D] Trying to add the function to the reftree...."
            
            try:
                self.reftree.add_func(ea)
            except Exception as detail:
                print detail

            if self.options['dev_mode']:
                print "[D] Succeeded adding function to reftree"
            
            # for undo operation
            if userEA == False:
                if self.options['dev_mode']:
                    print "DEBUG> setting last_history_added to 0x%08x" % top
                self.last_history_added = top

            if self.options['verbosity'] > 5:
                print "[*] ui.py: added 0x%08x to history" % ea

        if add == False:
            if self.options['dev_mode']:
                print "DEBUG> add is false, treewidget.clear()'ing"
                treewidget.clear()
        
        for graph in self.reftree.makeTrees():
            self.createChildrenItems(graph, treewidget)        

        if self.options['dev_mode']:
            print 'addtohistory: about to call refreshstrings/marks/imports'

        self.refreshStrings()
        self.refreshMarks(local=True)
        self.refreshCmts()
        self.refreshImports()


    def JumpMark(self):
        if self.options['dev_mode']:
            print "[D] JumpMark: printing stack:"
            traceback.print_stack()
            
        try:
            self.tabs.setCurrentWidget(self.markTab)
        except Exception as detail:
            print detail


    def CreateMark(self):
        if self.options['dev_mode']:
            print "[D] CreateMark: printing stack:"
            traceback.print_stack()
            
        class MarkDialog(QtGui.QDialog):
            def __init__(self, ui_obj, parent=None):
                super(MarkDialog, self).__init__(parent)

                self.ui_obj = ui_obj
                self.field1 = QtGui.QInputDialog()
                self.field2 = QtGui.QInputDialog()
                self.field1.setOption(QtGui.QInputDialog.NoButtons)
                self.field2.setOption(QtGui.QInputDialog.NoButtons)
                self.field1.setLabelText("Description:")
                self.field2.setLabelText("Optional Group:")

                self.field1.keyPressEvent = self.keyPressEvent
                self.field2.keyPressEvent = self.keyPressEvent
                
                confirm = QtGui.QPushButton("Add Mark")
                confirm.clicked.connect(self.add_mark)

                layout = QtGui.QVBoxLayout()
                layout.addWidget(self.field2)
                layout.addWidget(self.field1)
                
                layout.addWidget(confirm)
                
                self.setLayout(layout)
                self.setWindowTitle("Create Mark")
                self.setWindowModality(QtCore.Qt.ApplicationModal)
                self.show()


            def add_mark(self):
                ea = self.ui_obj.provider.currentEA()
                if self.ui_obj.options['architecture'] == "32":
                    print "[*] Adding a mark at 0x%08x" % ea
                else:
                    print "[*] Adding a mark at 0x%016x" % ea

                description = self.field1.textValue()
                group = self.field2.textValue()

                funcaddr = self.ui_obj.provider.funcStart(ea)
                if funcaddr == None:
                    funcaddr = ea

                if len(group) == 0:
                    self.ui_obj.master.tag(ea, 'mark', description)

                else:
                    self.ui_obj.master.tag(ea, 'mark', description)
                    self.ui_obj.master.tag(ea, 'group', group)
                
                
                self.done(1)
                self.hide()
                self.ui_obj.refreshMarks()
                self.ui_obj.refreshMarks(local=True)


            def keyPressEvent(self, event):
                if event.key() == QtCore.Qt.Key_Return:
                    self.done(1)
                    self.add_mark()

        mark = MarkDialog(self)
        self.refreshMarks()
        self.refreshMarks(local=True)

    def launch_Analysis(self):
        x = Analysis(self)
        x.Show("Function Queries")

    def PathStart(self):
        if self.options['dev_mode']:
            print "[D] PathStart: printing stack:"
            traceback.print_stack()
            
        ea         = self.provider.currentEA()
        func_name2 = None
        try:
            func_top  = function.top(ea)
            func_name = database.name(func_top)
            offset = ea - func_top
            try:
                func_name2 = self.provider.demangleName(func_name)
            except Exception as detail:
                if self.options['verbosity'] > 2:
                    print detail
                pass
        except Exception as detail:
            if self.options['architecture'] == "32":
                print "Problem setting path start to 0x%08x" % ea
            else:
                print "Problem setting path start to 0x%016x" % ea
            func_name = ""

        if func_name2 != None:
            func_name = func_name2

        if self.options['architecture'] == "32":
            self.pathStart.setText("Start address: 0x%08x, %s+0x%x" % (self.provider.currentEA(), func_name, offset))
        else:
            self.pathStart.setText("Start address: 0x%016x, %s+0x%x" % (self.provider.currentEA(), func_name, offset))

        self.pathStartAddress = func_top
        self.tabs.setCurrentWidget(self.pathfindingTab)


    def PathEnd(self):
        if self.options['dev_mode']:
            print "[D] PathEnd: printing stack:"
            traceback.print_stack()
            
        ea         = self.provider.currentEA()
        func_name2 = None
        try:
            func_top  = function.top(ea)
            func_name = database.name(func_top)
            offset    = ea - func_top
            
            try:
                func_name2 = self.provider.demangleName(func_name)
            except:
                pass
        
        except Exception as detail:
            if self.options['architecture'] == "32":
                print "Problem setting path end to 0x%08x" % ea
            else:
                print "Problem setting path end to 0x%016x" % ea
            func_name = ""

        if func_name2 != None:
            func_name = func_name2

        if self.options['architecture'] == "32":
            self.pathEnd.setText("End address: 0x%08x, %s+0x%x" % (self.provider.currentEA(), func_name, offset))
        else:
            self.pathEnd.setText("End address: 0x%016x, %s+0x%x" % (self.provider.currentEA(), func_name, offset))

        self.pathEndAddress = ea
        self.tabs.setCurrentWidget(self.pathfindingTab)


    def BBPathStart(self):
        if self.options['dev_mode']:
            print "[D] BBPathStart: printing stack:"
            traceback.print_stack()
            
        ea = self.provider.currentEA()
        try:
            func_top = function.top(ea)
            func_name = database.name(func_top)
            offset = ea - func_top
            try:
                func_name = self.provider.demangleName(func_name)
            except:
                pass
        except Exception as detail:
            if self.options['architecture'] == "32":
                print "Problem setting path start to 0x%08x" % ea
            else:
                print "Problem setting path start to 0x%016x" % ea
            func_name = ""

        if self.options['architecture'] == "32":
            self.bbpathStart.setText("Start address: 0x%08x, %s+0x%x" % (self.provider.currentEA(), func_name, offset))
        else:
            self.bbpathStart.setText("Start address: 0x%016x, %s+0x%x" % (self.provider.currentEA(), func_name, offset))
        self.bbpathStartAddress = ea
        self.tabs.setCurrentWidget(self.pathfindingTab)


    def BBPathEnd(self):
        if self.options['dev_mode']:
            print "[D] BBPathEnd: printing stack:"
            traceback.print_stack()
            
        ea = self.provider.currentEA()
        try:
            func_top = function.top(ea)
            func_name = database.name(func_top)
            offset = ea - func_top
            try:
                func_name = self.provider.demangleName(func_name)
            except:
                pass
        except Exception as detail:
            if self.options['architecture'] == "32":
                print "Problem setting path end to 0x%08x" % ea
            else:
                print "Problem setting path end to 0x%016x" % ea
            func_name = ""

        if self.options['architecture'] == "32":
            self.bbpathEnd.setText("End address: 0x%08x, %s+0x%x" % (self.provider.currentEA(), func_name, offset))
        else:
            self.bbpathEnd.setText("End address: 0x%016x, %s+0x%x" % (self.provider.currentEA(), func_name, offset))

        self.bbpathEndAddress = ea
        self.tabs.setCurrentWidget(self.pathfindingTab)


    def plot_bb_path(self):
        if self.options['dev_mode']:
            print "[D] plot_bb_path: printing stack:"
            traceback.print_stack()
        
        pf = pathfinder.BlockPathFinder()

        # XXX should cache this in a dict
        pf.analyseFunction()
        print "[*] BlockPathFinder: finished analyzing the current function" 

        ea = self.provider.currentEA()
        affected = set([])
        found_path = pf.findPathBlocks(ea, affected)
        
        if found_path:
            print "[*] BlockPathFinder: finished finding paths, bb count=%d" % len(affected)
        else:
            if self.options['architecture'] == "32":
                print "[!] BlockPathFinder: couldn't find any paths to 0x%08x" % ea
            else:
                print "[!] BlockPathFinder: couldn't find any paths to 0x%016x" % ea
            return

        edges = {}
        for b in affected:
            edges[b] = pf.children[b] & affected
        pg = pathfinder.BlockPathGraph(hex(ea), affected, edges, pf.blockInfo, self.options)
        pg.Show()


    def plot_path(self):
        if self.options['dev_mode']:
            print "[D] plot_path: printing stack:"
            traceback.print_stack()
            
        if not hasattr(self, 'pathStartAddress') or not hasattr(self, 'pathEndAddress'):
            print "[!] Cannot plot a path without both a start and an end address defined"
            return
        starttime = time.time()
        pf = pathfinder.FunctionPathFinder(self.master)
        pf.addStartFunction(self.pathStartAddress)
        affected = set([])
        found_path = pf.findPaths(self.pathEndAddress, affected, set([self.pathEndAddress]), 0, 9999)
        if found_path:
            edges = {}
            for c in affected:
                edges[c] = set(self.master.function_data[c]['parents']) & affected
                #edges[c] = set(self.master.xrefs_to(c)) & affected
            pg = pathfinder.PathGraph(self.pathEndAddress, affected, edges, self)
            pg.Show()
        else:
            if self.options['architecture'] == "32":
                print "[!] No paths found from 0x%08x => 0x%08x" % (self.pathStartAddress, self.pathEndAddress)
            else:
                print "[!] No paths found from 0x%016x => 0x%016x" % (self.pathStartAddress, self.pathEndAddress)
        print "Total run time in seconds: %d" % (time.time() - starttime)


    def deleteLocalMark(self):
        if self.options['dev_mode']:
            print "[D] deleteLocalMark: printing stack:"
            traceback.print_stack()
            
        selected = self.local_marks.selectedItems()

        for s in selected:
            address = int(s.text(3), 16)
            
            self.master.deleteTag(address, 'mark')
            try:
                #group = s.text(2)
                self.master.deleteTag(address, 'group')
            except Exception as detail:
                print detail

        self.rightClickMenuActive = False

        self.refreshMarks()
        self.refreshMarks(local=True)


    def deleteGlobalMark(self):
        if self.options['dev_mode']:
            print "[D] deleteGlobalMark: printing stack:"
            traceback.print_stack()
            
        selected = self.markList.selectedItems()
        
        for s in selected:
            address = int(s.text(3), 16)

            self.master.deleteTag(address, 'mark')
            try:
                #group = s.text(2)
                self.master.deleteTag(address, 'group')
            except Exception as detail:
                print detail

        self.rightClickMenuActive = False

        self.refreshMarks()
        self.refreshMarks(local=True)



    def matchHistoryItem(self, widgetitem, param):

        bgbrush = QtGui.QBrush(QtGui.QColor(self.options['background_color']))
        fgbrush = QtGui.QBrush(QtGui.QColor(self.options['font_color']))

        bgbrush_highlight = QtGui.QBrush(QtGui.QColor(self.options['highlighted_background']))
        fgbrush_highlight = QtGui.QBrush(QtGui.QColor(self.options['highlighted_foreground']))
        
        text = widgetitem.text(1)
        address = int(str(text), 16)
       
        if address == param:
            widgetitem.setForeground(0, fgbrush_highlight)
            widgetitem.setForeground(1, fgbrush_highlight)
            widgetitem.setBackground(0, bgbrush_highlight)
            widgetitem.setBackground(1, bgbrush_highlight)
        else:
            widgetitem.setForeground(0, fgbrush)
            widgetitem.setForeground(1, fgbrush)
            widgetitem.setBackground(0, bgbrush)
            widgetitem.setBackground(1, bgbrush)


        for childidx in xrange(0, widgetitem.childCount()):
            self.matchHistoryItem(widgetitem.child(childidx), param) 


    def refreshHistory(self, local=False):

        currentEA = self.provider.currentEA()
        func_top = self.provider.funcStart(currentEA)
        
        # XXX this seems like a stupid thing to do, self. removing.
        #if not func_top:
        #    return

        bgbrush = QtGui.QBrush(QtGui.QColor('darkgreen'))
        fgbrush = QtGui.QBrush(QtGui.QColor('white'))

        toplevelcount = self.history_obj.topLevelItemCount()

        for i in xrange(0, toplevelcount):
            toplevelitem = self.history_obj.topLevelItem(i)

            text = toplevelitem.text(1)
            address = int(str(text), 16)

            if address == func_top:
                toplevelitem.setForeground(0, fgbrush)
                toplevelitem.setForeground(1, fgbrush)
                toplevelitem.setBackground(0, bgbrush)
                toplevelitem.setBackground(1, bgbrush)
                self.matchHistoryItem(toplevelitem, func_top)
            else:
                toplevelitem.setForeground(0, QtGui.QBrush(QtGui.QColor(self.options['font_color'])))
                toplevelitem.setForeground(1, QtGui.QBrush(QtGui.QColor(self.options['font_color'])))
                toplevelitem.setBackground(0, QtGui.QBrush(QtGui.QColor(self.options['background_color'])))
                toplevelitem.setBackground(1, QtGui.QBrush(QtGui.QColor(self.options['background_color'])))
                self.matchHistoryItem(toplevelitem, func_top)

    def refreshCmts(self):
        if self.options['dev_mode']:
            print "[D] refreshCmts: printing stack:"
            traceback.print_stack()

        self.localview.clear()
        comment_dict  = pickle.loads(self.fs.load("default.cmts"))
        rcomment_dict = pickle.loads(self.fs.load("default.rcmts"))

        current_ea = self.provider.currentEA()
        dicts = [comment_dict, rcomment_dict]
        for d in dicts:
            for addy, comm in d.iteritems():

                is_import = False
                try:
                    function.top(addy)
                except ValueError:
                    is_import = True

                try:
                    if not function.contains(current_ea, addy):
                        continue
                except ValueError as detail:
                    # likely import
                    is_import = True
                    if current_ea != addy:
                        continue
            
                cmt_item = QtGui.QTreeWidgetItem(self.localview)

                if is_import:
                    func_top = addy
                else:
                    func_top = function.top(addy)

                offset = addy - func_top
                func_name  = self.provider.getName(func_top)
                func_name2 = self.provider.demangleName(func_name)
                
                # in case Demangle returns None
                if func_name2: 
                    func_name = func_name2

                if len(func_name) == 0:
                    symbol = hex(addy)
                else:
                    symbol = func_name + "+" + "0x%x" % offset

                font = QtGui.QFont(self.options['font_name'], int(self.options['font_size']))
                cmt_item.setFont(0, font)
                cmt_item.setFont(1, font)
                cmt_item.setFont(2, font)

                cmt_item.setText(0, comm)
                cmt_item.setText(1, "%s" % symbol)
            

                if self.options['architecture'] == "32":
                    cmt_item.setText(2, "0x%08x" % addy)
                else:
                    cmt_item.setText(2, "0x%016x" % addy)

                cmt_item.setExpanded(True)


    def refreshMarks(self, local=False):
        if self.options['dev_mode']:
            print "[D] refreshMarks: printing stack:"
            traceback.print_stack()
            
        # ensure we aren't accidentally de-selecting something via a refresh while a context menu is active
        if self.rightClickMenuActive:
            return

        if local:
            mark_obj = self.local_marks
        else:
            mark_obj = self.markList

        selected_address = None
        selected = mark_obj.selectedItems()
        if selected != []:
            selected_address = selected[0].text(3)

        marks = self.master.getAttribute('mark')
        groups = self.master.getAttribute('group')

        mark_obj.clear()
        for mark_ea, data in marks.iteritems():

            is_import = False
            # skip marks not in code
            try:
                function.top(mark_ea)
            except ValueError:
                is_import = True

            if local:
                current_ea = self.provider.currentEA()
                try:
                    if not function.contains(current_ea, mark_ea):
                        continue
                except ValueError as detail:
                    # likely import
                    is_import = True
                    if current_ea != mark_ea:
                        continue


            # check if its part of a group
            if groups.has_key(mark_ea):

                # XXX: we need to ensure we don't have it already in the list
                mark_item = QtGui.QTreeWidgetItem(mark_obj)
                mark_description = data['mark']           

                if is_import:
                    func_top = mark_ea
                else:
                    func_top = function.top(mark_ea)

                offset = mark_ea - func_top
                func_name = self.provider.getName(func_top)

                func_name2 = self.provider.demangleName(func_name)
                
                # in case Demangle returns None
                if func_name2: 
                    func_name = func_name2

                if len(func_name) == 0:
                    symbol = hex(mark_ea)
                else:
                    symbol = func_name + "+" + "0x%x" % offset

                group_text = groups[mark_ea]['group']

                font = QtGui.QFont(self.options['font_name'], int(self.options['font_size']))
                mark_item.setFont(0, font)
                mark_item.setFont(1, font)
                mark_item.setFont(2, font)
                mark_item.setFont(3, font)

                mark_item.setText(0, mark_description)
                mark_item.setText(1, "%s" % symbol)
                mark_item.setText(2, group_text)

                if self.options['architecture'] == "32":
                    mark_item.setText(3, "0x%08x" % mark_ea)
                else:
                    mark_item.setText(3, "0x%016x" % mark_ea)

                mark_item.setExpanded(True)
                del(font)
  
            else:
                mark_item = QtGui.QTreeWidgetItem(mark_obj)
                mark_description = data['mark']           

                if is_import:
                    func_top = mark_ea
                else:
                    func_top = function.top(mark_ea)
                
                offset = mark_ea - func_top
                func_name = self.provider.getName(func_top)
                func_name2 = self.provider.demangleName(func_name)
                
                # in case Demangle returns None
                if func_name2: 
                    func_name = func_name2
                
                if len(func_name) == 0:
                    symbol = hex(mark_ea)
                else:
                    symbol = func_name + "+" + "0x%x" % offset

                group_text = ''

                font = QtGui.QFont(self.options['font_name'], int(self.options['font_size']))
                mark_item.setFont(0, font)
                mark_item.setFont(1, font)
                mark_item.setFont(2, font)
                mark_item.setFont(3, font)

                mark_item.setText(0, mark_description)
                mark_item.setText(1, "%s" % symbol)
                mark_item.setText(2, group_text)

                if self.options['architecture'] == "32":
                    mark_item.setText(3, "0x%08x" % mark_ea)
                else:
                    mark_item.setText(3, "0x%016x" % mark_ea)

                mark_item.setExpanded(True)
                del(font)

            # reset anything that was selected prior to the timer de-selecting it
            x = mark_obj.findItems(selected_address, QtCore.Qt.MatchExactly, column=3)
            if x != []:
                x[0].setSelected(True)


    
    def markClicked(self, item, column):
        if self.options['dev_mode']:
            print "[D] markClicked: printing stack:"
            traceback.print_stack()
            
        # get the address from the column
        address_line = item.data(3, 0)
        address = int(address_line, 16)
        database.go(address)

    def localCmtClicked(self, item, column):
        if self.options['dev_mode']:
            print "[D] localCmtClicked: printing stack:"
            traceback.print_stack()
            
        address_line = item.data(2, 0)
        address = int(address_line, 16)
        database.go(address)

    def localMarkClicked(self, item, column):
        if self.options['dev_mode']:
            print "[D] localMarkClicked: printing stack:"
            traceback.print_stack()
            
        address_line = item.data(3, 0)
        address = int(address_line, 16)
        database.go(address)
        

    def historyClicked(self, item, column):
        if self.options['dev_mode']:
            print "[D] historyClicked: printing stack:"
            traceback.print_stack()
            
        col2_data = item.data(1,0)
        try:
            addr = int(col2_data, 16)
            database.go(addr)
            self.refreshMarks(local=True)
            self.refreshCmts()

            if self.show_imports == True:
                self.refreshImports()
            if self.show_strings == True:
                self.refreshStrings()

        except Exception as detail:
            print '[!] Failed to jump to address clicked in history tree, %s' % detail
            pass

        

    def saveHistory(self, default=False, userRefTree=None):
        if self.options['dev_mode']:
            print "[D] saveHistory: printing stack:"
            traceback.print_stack()
            
        if default:
            filename = "default.sess"

        else:
            text = QtGui.QInputDialog().getText(None, "Save History", "Enter filename:")
            filename = str(text[0])

        if filename == "":
            return

        if not filename.endswith(".sess"):
            filename += ".sess"

        print "[+] Saving history object as %s" % filename

        tmp = tempfile.TemporaryFile(mode='wb')
        tmpname = tmp.name
        tmp.close()

        if not userRefTree:
            tree = self.reftree
        else:
            tree = userRefTree

        pickled_file = open(tmpname, "wb")
        pickle.dump(tree, pickled_file)
        pickled_file.close()

        fh = open(tmpname, "rb")
        graphObj_data = fh.read()
        fh.close()

        self.fs.store(filename, graphObj_data)
        self.refreshFilesystem()


    def clearHistory(self):
        if self.options['dev_mode']:
            print "[D] clearHistory: printing stack:"
            traceback.print_stack()
            
        treewidget = self.history_obj
        treewidget.clear()
        self.reftree = RefTree.RefTree(self.master, function_data={})
        self.localview.clear()


    def deleteFile(self):
        if self.options['dev_mode']:
            print "[D] deleteFile: printing stack:"
            traceback.print_stack()
            
        try:
            selected = self.fsTree.selectedItems()[0]
        except:
            print "[!] No file selected"
            self.rightClickMenuActive = False
            return 
        
        delete_me = selected.text(0)

        self.fs.delete(delete_me)

        self.rightClickMenuActive = False

        self.refreshFilesystem()


    def refreshFilesystem(self):
        if self.options['dev_mode']:
            print "[D] refreshFilesystem: printing stack:"
            traceback.print_stack()
            
        names = self.fs.list_files()
        
        self.fsTree.clear()
        
        for n in names:
            if n == '__internal__': continue

            size = len(self.fs.load(n))
            rootWidget = QtGui.QTreeWidgetItem(self.fsTree)
            font = QtGui.QFont(self.options['font_name'], int(self.options['font_size']))
            rootWidget.setFont(0, font)
            rootWidget.setFont(1, font)          
            rootWidget.setText(0, n)
            rootWidget.setText(1, "%d" % size)

            ext = n.split(".")[-1]
            rootWidget.setText(2, "%s" % ext)
            rootWidget.setExpanded(True)


    def applyFile(self):
        if self.options['dev_mode']:
            print "[D] applyFile: printing stack:"
            traceback.print_stack()
            
        try:
            selected = self.fsTree.selectedItems()[0].text(0)
        except:
            print '[!] No file selected'
            self.rightClickMenuActive = False
            return

        if ".marks" in selected[-6:]:
            obj_data = self.fs.load(selected)
            marks,groups = pickle.loads(obj_data)
            
            for mark_ea, mark in marks.iteritems():
                self.master.tag(mark_ea, 'mark', mark['mark'])

            self.refreshMarks()
            
        elif ".cmts" in selected[-5:]:
            obj_data = self.fs.load(selected)
            x = Applier(self, selected, "cmts")
            x.Show("Comments")

        elif ".rcmts" in selected[-6:]:
            obj_data = self.fs.load(selected)
            x = Applier(self, selected, "rcmts")
            x.Show("Repeatable Comments")

        else:
            print "[!] You can only 'Apply' comments, names, or marks"
            self.rightClickMenuActive = False
            return

        self.rightClickMenuActive = False

    def addFile(self):  
        if self.options['dev_mode']:
            print "[D] addFile: printing stack:"
            traceback.print_stack()
            
        filename = str(QtGui.QFileDialog.getOpenFileName(self.fsTree, "Add File", os.sep, "All Files (*.*)")[0])
        
        print "[*] Adding file '%s' from disk to the filesystem." % filename
        try:
            fh = open(filename, 'rb')
        except:
            print "[!] Error loading file %s" % filename
            self.rightClickMenuActive = False
            return
        filename = filename.split("/")[-1]
        self.fs.store_fh(fh, filename)

        self.rightClickMenuActive = False

        self.refreshFilesystem()


    def pushPeers(self):
        if self.options['dev_mode']:
            print "[D] pushPeers: printing stack:"
            traceback.print_stack()
            
        try:
            selected = self.fsTree.selectedItems()[0].text(0)
        except:
            print '[!] No file selected'
            self.rightClickMenuActive = False
            return

        obj_data = self.fs.load(selected)

        for peer in self.peers:
            self.myhost.sendPeer(obj_data, "generic", selected, params=None, idx=peer)

        self.rightClickMenuActive = False


    def mergeSessFiles(self):
        if self.options['dev_mode']:
            print "[D] mergeSessFiles: printing stack:"
            traceback.print_stack()
            
        selected = self.fsTree.selectedItems()
        if len(selected) < 2:
            print "[!] You must have at least 2 session files selected to merge"
            self.rightClickMenuActive = False
            return

        fnames = []
        to_merge = []
        for s in selected:

            txt = str(s.text(0))
            fnames.append(txt)
            if not txt.endswith(".sess"):
                print "[!] You can only merge .sess files"
                self.rightClickMenuActive = False
                return
            try:
                obj_data = self.fs.load(txt)
            except:
                print "[!] Error loading session file %s from filesystem" % txt
                self.rightClickMenuActive = False
                return

            try:
                obj_des = pickle.loads(obj_data)
            except:
                print "[!] Error deserializing session file %s" % txt
                self.rightClickMenuActive = False
                return

            if obj_des != None:
                to_merge.append(obj_des)

        treewidget = self.history_obj
        treewidget.clear()

        self.reftree = RefTree.RefTree(masterGraph=self.master)

        eas = set()
        for obj in to_merge:
            for func in obj.function_data.keys():
                eas.add(func)

        eas = list(eas)

        print "[*] Merging %s, total function count=%d" % (repr(fnames), len(eas))

        for ea in eas:
            self.addToHistory(userEA=ea)
 
        self.tabs.setCurrentWidget(self.historyTab)

        self.rightClickMenuActive = False


    def loadSessFile(self, default=False):
        if self.options['dev_mode']:
            print "[D] loadSessFile: printing stack:"
            traceback.print_stack()
            
        if default:
            selected = "default.sess"

        else:
            try:
                selected = self.fsTree.selectedItems()[0].text(0)
            except:
                print '[!] No file selected'
                self.rightClickMenuActive = False
                return

            
        if selected.endswith(".sess"):

            obj_data = self.fs.load(selected)
            try:
                obj = pickle.loads(obj_data)
            except TypeError:
                print "[!] Tried to load a file %s that may not exist" % selected
                self.addToHistory(add=False)
                self.rightClickMenuActive = False
                return False

            print '[*] Loading session file %s' % selected
            treewidget = self.history_obj
            treewidget.clear()
            self.reftree = RefTree.RefTree(self.master, function_data=obj.function_data)
            self.addToHistory(add=False)
            self.refreshMarks(local=True)
            self.refreshCmts()
            self.tabs.setCurrentWidget(self.historyTab)


        self.rightClickMenuActive = False


    def applyOptions(self):
        if self.options['dev_mode']:
            print "[D] applyOptions: printing stack:"
            traceback.print_stack()
            
        # yeah, we're really doing this
        x = self.dynamicOptions
        txt = "self."
        txt += str(x.toPlainText())
        try:
            y = compile(txt, '<string>', 'exec')
            eval(y)

        # It says on your chart that you're fucked up. Uh, you talk like a fag, and your shit's all retarded.
        except Exception as detail:
            print "[!] Tried setting our options on the fly, but failed: %s" % detail

        print "[*] Successfully updated options"


    def saveToRetVals(self):
        if self.options['dev_mode']:
            print "[D] saveToRetVals: printing stack:"
            traceback.print_stack()
            
        try:
            selected = self.fsTree.selectedItems()[0].text(0)
        except:
            print '[!] No file selected'
            self.rightClickMenuActive = False
            return

        obj_data = self.fs.load(selected)
        try:
            obj = pickle.loads(obj_data)
        except TypeError:
            print "[!] Tried to load a file %s that may not exist" % selected
            self.rightClickMenuActive = False
            return False
        except KeyError:
            obj = obj_data

        fname, ok = QtGui.QInputDialog().getText(None, "Save to variable", "Enter variable name:", QtGui.QLineEdit.Normal, "")

        try:
            print "[*] Saving file %s into global variable dictionary toolbag.toolbag.retvals with key '%s'" % (selected, fname)
            self.global_hook.retvals[fname] = obj
        except Exception as detail:
            print "[!] Failed to set toolbag.toolbag.retvals[%s] to the object data in %s" % (fname, selected)
            if self.options['verbosity'] > 2:
                print detail

        self.rightClickMenuActive = False

    def exportFile(self):
        if self.options['dev_mode']:
            print "[D] exportFile: printing stack:"
            traceback.print_stack()
            
        try:
            selected = self.fsTree.selectedItems()[0].text(0)
        except:
            print '[!] No file selected'
            self.rightClickMenuActive = False
            return

        filename = str(QtGui.QFileDialog.getSaveFileName(self.fsTree, "Export File", os.sep, "All Files (*.*)")[0])
        
        print "[*] Exporting file '%s' to disk as '%s'" % (selected, filename)
        try:
                fh = open(filename, 'wb')
        except:
                print "[!] Error saving file %s" % filename
                self.rightClickMenuActive = False
                return
        data = self.fs.load(selected)
        fh.write(data)
        fh.close()

        self.rightClickMenuActive = False

        self.refreshFilesystem()


    def importCallClicked(self, item, column):
        if self.options['dev_mode']:
            print "[D] importCallClicked: printing stack:"
            traceback.print_stack()
            
        address_line = item.data(2, 0)
        address = int(address_line, 16)
        database.go(address)
        self.refreshImports()


    def refreshImports(self, local=True):
        if self.options['dev_mode']:
            print "[D] refreshImports: printing stack:"
            traceback.print_stack()
            
        self.import_calls.clear()

        if self.show_imports == True:
            self.import_calls.setVisible(True)
        else:
            self.import_calls.setVisible(False)

        # ripped from http://code.google.com/p/idapython/source/browse/trunk/examples/ex_imports.py

        # this should really be a class variable instead of being dynamically generated so often...
        import_dict = {}

        def imp_cb(ea, name, ord):

            if name:
                dname = self.provider.demangleName(name)
                if dname == None:
                    dname = name
                import_dict[iname][dname] = ea
                
            return True

        nimps = self.provider.numImports()
        for i in xrange(0, nimps):
            iname = self.provider.importName(i)
            if not iname: continue
            import_dict[iname] = {}
            self.provider.enumImportNames(i, imp_cb)

        try:
            # this is pretty terrible, fyi. 
            # such attributes should be stored in the database
            # as our schema affords it.
            # 
            # we do so with our analyzers/collectors in the priv8 version 
            addy = self.provider.currentEA()
            funcs = list(self.reftree.listChildren(self.reftree.makeTree(addy)))
        
            proc = self.provider.getArch()

            if proc in ["arm", "ppc", "mips"]:
                idata = "extern"
            elif proc == "pc":
                idata = ".idata"

            try:
                idata = segment.get(idata)
            except KeyError:
                if self.options['verbosity'] > 2:
                    print "[!] Failure looking up import section (%s)" % idata
                return

            idata_bounds = (segment.top(idata), segment.bottom(idata))
            for f in funcs:
                startEA = self.provider.funcStart(f)
                endEA = self.provider.funcEnd(f)

                if startEA == None or endEA == None: 
                    continue

                # loop the obvious instructions *and* function chunks
                all_addresses = list(self.provider.iterInstructions(startEA, endEA))
                all_addresses.extend(self.provider.iterFuncChunks(startEA))
                all_addresses = list(set(all_addresses))

                for instr in all_addresses:

                    disasm = self.provider.getDisasm(instr)
                    if not (disasm.startswith("call") or disasm.startswith("j")):
                        continue
                        
                    unique = set()
                    try:
                        ref = database.down(instr)
                        if ref == []:
                            continue
                        else:
                            for r in ref:
                                # check for .idata section
                                if r >= idata_bounds[0] and r <= idata_bounds[1]:

                                    # check the set
                                    if instr in unique:
                                        continue
                                    else:
                                        unique.add(instr)

                                    # add it
                                    name = self.provider.demangleName(self.provider.getName(r))
                                    if name == None:
                                        name = self.provider.getName(r)

                                    modname = ""
                                    for module, vals in import_dict.iteritems():

                                        for func, addy in vals.iteritems():
                                            if addy == r:
                                                modname = module
                                                break

                                    item = QtGui.QTreeWidgetItem(self.import_calls)
                                    item.setText(0, "%s!%s" % (modname,name))
                                    caller_name = self.provider.demangleName(self.provider.getName(startEA))
                                    if caller_name == None:
                                        caller_name = self.provider.getName(startEA)  
                                    item.setText(1, "%s" % caller_name)

                                    if self.options['architecture'] == "32":
                                        item.setText(2, "0x%08x" % instr)
                                    else:
                                        item.setText(2, "0x%016x" % instr)

                    except Exception as detail:
                        print '[!] Fail1, %s' % detail

        except IndexError:
            pass
        except Exception as detail:
            print '[!] refreshImports, %s' % detail
            raise


    def refreshStrings(self, local=True):
        if self.options['dev_mode']:
            print "[D] refreshStrings: printing stack:"
            traceback.print_stack()
            
        if self.show_strings == True:
            self.string_refs.setVisible(True)
        else:
            self.string_refs.setVisible(False)
        self.string_refs.clear()

        try:
            # this is pretty terrible, fyi. 
            # such attributes should be stored in the database
            # as our schema affords it.
            # 
            # we do so with our analyzers/collectors in the priv8 version 
            addy = self.provider.currentEA()
            funcs = list(self.reftree.listChildren(self.reftree.makeTree(addy)))
            
            self.string_refs.clear()

            for f in funcs:
                startEA = self.provider.funcStart(f)
                endEA = self.provider.funcEnd(f)

                # loop the obvious instructions *and* function chunks
                all_addresses = list(self.provider.iterInstructions(startEA, endEA))
                all_addresses.extend(self.provider.iterFuncChunks(startEA))
                all_addresses = list(set(all_addresses))

                for instr in all_addresses:
                    unique = set()
                    try:
                        ref = database.down(instr)
                        if ref == []:
                            continue
                        else:
                            for r in ref:
                                # check flags
                                res = self.provider.isString(r)
                                if res:
                                    if instr in unique:
                                        continue
                                    else:
                                        unique.add(instr)

                                    value = self.provider.getString(r)
                                    value = value.replace("\n", "\\n ")
                                    
                                    item = QtGui.QTreeWidgetItem(self.string_refs)
                                    item.setText(0, "%s" % value)
                                    caller_name = self.provider.demangleName(self.provider.getName(startEA))
                                    if caller_name == None:
                                        caller_name = self.provider.getName(startEA)  
                                    item.setText(1, "%s" % caller_name)

                                    if self.options['architecture'] == "32":
                                        item.setText(2, "0x%08x" % instr)
                                    else:
                                        item.setText(2, "0x%016x" % instr)

                    except Exception as detail:
                        print '[!] Failed adding a string reference (refreshStrings), %s' % detail

        #except IndexError:
        #    print "INDEXERROR"
        #    pass
        except Exception as detail:
            pass
            #print '[!] refreshStrings, %s' % detail


    def removeNode(self):
        try:
            selected = self.history_obj.selectedItems()[0].text(1)
        except Exception as detail:
            print "[!] You must select a node to perform a query!"
            return

        addy = int(selected, 16)
        try:
            # find addy in self.reftree and remove it
            x = self.reftree.function_data
            self.reftree.function_data = {key: value for key, value in x.items() if key != addy}

            # find addy in the PySide QTreeWidget and remove it
            if self.options['architecture'] == '32':
                occs = self.history_obj.findItems("0x%08x" % addy, QtCore.Qt.MatchExactly, column=1)
            elif self.options['architecture'] == '64':
                occs = self.history_obj.findItems("0x%016x" % addy, QtCore.Qt.MatchExactly, column=1)
            else:
                print "[!] Unknown architecture %s!" % self.options['architecture']
                return

            print "[*] Found %d occurrences of requested node" % len(occs)

            for occ in occs:
                idx = self.history_obj.indexOfTopLevelItem(occ)
                self.history_obj.takeTopLevelItem(idx)

            print "[*] Done removing nodes, refreshing history view"
            self.refreshHistory()

        except Exception as detail:
            print "[!] Error trying to remove node from history: %s" % detail


    def queryGraph(self):
        if self.options['dev_mode']:
            print "[D] queryGraph: printing stack:"
            traceback.print_stack()
            
        try:
            selected = self.history_obj.selectedItems()[0].text(1)
        except Exception as detail:
            print "[!] You must select a node to perform a query!"
            return

        addy = int(selected, 16)

        depth_val = QtGui.QInputDialog().getInt(None, "Query DB", "Depth (positive or negative):")[0]

        # hawt
        new_window = Query(self, addy, depth_val)

        self.new_windows.append(new_window)

        try:
            name = self.provider.demangleName(self.provider.getName(addy))
            if name == None:
                name = database.name(addy)

            if name == None or len(name) == 0:
                if self.options['architecture'] == "32":
                    name = "0x%08x" % addy
                else:
                    name = "0x%016x" % addy

            if self.options['architecture'] == "32":
                new_window.Show("Custom Query - Depth %d from %s (0x%08x)" % (depth_val, name, addy))
            else:
                new_window.Show("Custom Query - Depth %d from %s (0x%016x)" % (depth_val, name, addy))

        except Exception as detail:
            print detail


    def pushMarksToPeers(self):
        if self.options['dev_mode']:
            print "[D] pushMarksToPeers: printing stack:"
            traceback.print_stack()
            
        # XXX: disabled right now? or did i do this w/ 'generic'? ... hmm.
        pass
        marks = self.master.getAttribute('mark')
        groups = self.master.getAttribute('group')

        data = pickle.dumps((marks, groups))

        for peer in self.peers:
            self.myhost.sendPeer(data, "marks", "marks.marks", params=None, idx=peer)
        #mark_obj.clear()
        #for mark_ea, data in marks.iteritems():
        #    self.sendPeer((marks, group), "marks", "marks.marks")
        #    pass

        self.rightClickMenuActive = False


    def gatherStrings(self):
        funcs_uniq = list(set(self.reftree.function_data.keys()))

        # gather all addresses
        all_addresses = []
        for f in funcs_uniq:
            startEA = self.provider.funcStart(f)
            endEA = self.provider.funcEnd(f)

            if startEA == None or endEA == None:
                continue

            # loop the obvious instructions *and* function chunks
            all_addresses.extend(self.provider.iterInstructions(startEA, endEA))
            all_addresses.extend(self.provider.iterFuncChunks(startEA))
            all_addresses = list(set(all_addresses))


        print "[*] Gathering strings across %d functions (%d instructions)" % (len(funcs_uniq), len(all_addresses))

        found = {}
        for instr in all_addresses:
            try:
                ref = database.down(instr)
                if ref == []:
                    continue
                else:
                    for r in ref:
                        # check flags
                        res = self.provider.isString(r)
                        if res:
                            value = self.provider.getString(r)
                            value = value.replace("\n", "\\n ")

                            if found.has_key(instr):
                                continue
                            else:
                                found[instr] = value

                            
            except Exception as detail:
                print '[!] Failed gathering strings: %s' % detail

        print "[*] Gathered %d strings from current history, result:" % len(found.keys())

        for address, stringvalue in found.iteritems():
            if self.options['architecture'] == "32":
                print "[*] 0x%08x: %s" % (address, stringvalue)
            elif self.options['architecture'] == "64":
                print "[*] 0x%016x: %s" % (address, stringvalue)
            else:
                print "[!] Unknown architecture!"

        


    def invokeQueues(self):
        if self.options['dev_mode']:
            print "[D] invokeQueues: printing stack:"
            traceback.print_stack()
            
        try:
            addresses = copy.deepcopy(self.reftree.function_data)
            data = pickle.dumps(addresses)
            for peer in self.peers:
                self.myhost.sendPeer(data, "reftree", "reftree.sess", params=None, idx=peer)
        except Exception as detail:
            print detail
            print '[!] Failed to send data to the queue'
        

    def addEdgeSource(self, userEA=False):
        if self.options['dev_mode']:
            print "[D] addEdgeSource: printing stack:"
            traceback.print_stack()
        
        if not userEA:
            self.edge_source = self.provider.currentEA()
        else:
            self.edge_source = userEA
        
        if self.options['architecture'] == "32":
            print "[*] Set 0x%08x as source of an edge" % self.edge_source
        else:
            print "[*] Set 0x%016x as source of an edge" % self.edge_source

    def addEdgeDest(self, userEA=False):
        if self.options['dev_mode']:
            print "[D] addEdgeDest: printing stack:"
            traceback.print_stack()
        
        if not userEA:
            self.edge_dest = self.provider.currentEA()
        else:
            self.edge_dest = userEA

        if self.options['architecture'] == "32":
            print "[*] Set 0x%08x as destination of an edge" % self.edge_dest
        else:
            print "[*] Set 0x%016x as destination of an edge" % self.edge_dest

        ea_type = self.provider.getFlags(self.edge_dest)

        if self.provider.isCode(ea_type):
            if self.edge_source:
                if self.options['architecture'] == "32":
                    print "[*] Adding an edge from 0x%08x to 0x%08x" % (self.edge_source, self.edge_dest)
                else:
                    print "[*] Adding an edge from 0x%016x to 0x%016x" % (self.edge_source, self.edge_dest)

                # add the edge to both the master and the current reftree
                self.master.addEdge(self.edge_source, self.edge_dest)
                self.reftree.addEdge(self.edge_source, self.edge_dest)
                
                # append a comment (dst) at the src
                cur = self.provider.getComment(self.edge_source)

                com = ""
                if (len(cur) > 0):
                    if self.options['architecture'] == "32":
                        com = cur + "\n" + "0x%08x" % self.edge_dest
                    else:
                        com = cur + "\n" + "0x%016x" % self.edge_dest
                else:
                    if self.options['architecture'] == "32":
                        com = "0x%08x" % self.edge_dest
                    else:
                        com = "0x%016x" % self.edge_dest
                
                self.provider.makeComment(self.edge_source, com)
                self.provider.refreshView()
                
                # add both to history view
                self.addToHistory(userEA=self.edge_dest)
                self.addToHistory(userEA=self.edge_source)

        else:
            print "[*] Asked to add an edge to something in non-code, looking for function pointers..."

            code_addys = []

            # iterate up to 100 dwords
            for head in self.provider.iterInstructions(self.edge_dest, self.edge_dest+(4*100)):
                dref = list(self.provider.dataRefs(head))
 
                if dref == []:
                    break
                    
                else:
                    addy_flags = self.provider.getFlags(dref[0])

                    if (addy_flags & self.provider.FUNC_FLAG) != 0:
                        code_addys.append(dref[0])

                    else:
                        break

            if len(code_addys) > 1:
                print "[*] Found %d code pointers to add as destinations" % len(code_addys)

            if self.edge_source:
                self.addToHistory(userEA=self.edge_source)

                comment = ""

                for addy in code_addys:
                    self.master.addEdge(self.edge_source, addy)
                    self.addToHistory(userEA=addy)
                    
                    name = self.provider.getName(addy)
                    demangled_name = self.provider.demangleName(name)

                    if demangled_name:
                        comment += "%s\n" % demangled_name
                    else:
                        comment += "%s\n" % name

                self.provider.makeComment(self.edge_source, comment)

        return


    def addEdge(self):
        if self.options['dev_mode']:
            print "[D] addEdge: printing stack:"
            traceback.print_stack()
            
        src = QtGui.QInputDialog().getText(None, "Add Edge", "Enter source address:")
        try:
            src = int(src[0], 16)
        except ValueError:
            return
        
        self.addToHistory(userEA=src)

        dst = QtGui.QInputDialog().getText(None, "Add Edge(s)", "Enter destination address(es), optionally separated by commas:")

        try:
            if "," in dst[0]:
                addys = dst[0].split(",")
            else:
                addys = [dst[0]]
            
            for addy in addys:
                dst = int(addy, 16)
                self.master.addEdge(src, dst)
                self.addToHistory(userEA=dst)

            print '[*] Added %d edges' % len(addys)

        except Exception as detail:
            print "[!] You gone dun brokes it, %s" % detail

        self.addToHistory()


    def toggleFileSystemTab(self):
        if self.options['dev_mode']:
            print "[D] toggleFileSystemTab: printing stack:"
            traceback.print_stack()
            
        done = False
        for i in xrange(0, self.tabs.count()):
            t = self.tabs.widget(i)
            if t:
                if t.windowTitle() == "File System":
                        self.tabs.removeTab(i)
                        done = True

        if not done:
            self.tabs.addTab(self.fsTab, "File System")


    def toggleUserScriptsTab(self):
        if self.options['dev_mode']:
            print "[D] toggleUserScriptsTab: printing stack:"
            traceback.print_stack()
            
        done = False
        for i in xrange(0, self.tabs.count()):
            t = self.tabs.widget(i)
            if t:
                if t.windowTitle() == "Scripts":
                        #self.view_menu.activeAction().setChecked(False)
                        self.tabs.removeTab(i)
                        done = True

        if not done:
            self.tabs.addTab(self.userScriptsTab, "Scripts")


    def togglePathfindingTab(self):
        if self.options['dev_mode']:
            print "[D] togglePathfindingTab: printing stack:"
            traceback.print_stack()
            
        done = False
        for i in xrange(0, self.tabs.count()):
            t = self.tabs.widget(i)
            if t:
                if t.windowTitle() == "Pathfinding":
                        #self.view_menu.activeAction().setChecked(False)
                        self.tabs.removeTab(i)
                        done = True

        if not done:
            self.tabs.addTab(self.pathFindingTab, "Pathfinding")


    def toggleOptionsTab(self):
        if self.options['dev_mode']:
            print "[D] toggleOptionsTab: printing stack:"
            traceback.print_stack()
            
        done = False
        for i in xrange(0, self.tabs.count()):
            t = self.tabs.widget(i)
            if t:
                if t.windowTitle() == "Options":
                        #self.view_menu.activeAction().setChecked(False)
                        self.tabs.removeTab(i)
                        done = True

        if not done:
            self.tabs.addTab(self.optionsTab, "Options")


    def viewSplash(self):
        if self.options['dev_mode']:
            print "[D] viewSplash: printing stack:"
            traceback.print_stack()
            
        # fuckin' python
        x = __import__("utils")
        reload(x)
        return


    def toggleQueueTab(self):
        if self.options['dev_mode']:
            print "[D] toggleQueueTab: printing stack:"
            traceback.print_stack()
            
        done = False
        for i in xrange(0, self.tabs.count()):
            t = self.tabs.widget(i)
            if t:
                if t.windowTitle() == "Queues":
                    self.tabs.removeTab(i)
                    done = True

        if not done:
            self.tabs.addTab(self.queueTab, "Queues")


    def addQueue(self):   
        if self.options['dev_mode']:
            print "[D] addQueue: printing stack:"
            traceback.print_stack()

        if not self.peerRadio.isChecked() and not self.serverRadio.isChecked() and not self.agentRadio.isChecked():
            print "[!] You must select either Server, Agent, or Peer when adding...stuff."
            return False

        key  = self.queueKeyObj.text()
        host = self.queueHostObj.text()
        port = int(self.queuePortObj.text())

        if port <= 1024 or port >= 65535:
            print "[!] Port number is invalid. Must be >= 1024 and <= 65535."
            return False

        if self.serverRadio.isChecked():

            # check if there's already a server
            count = self.queueList.topLevelItemCount()
            for i in xrange(0, count):
                item = self.queueList.topLevelItem(i)
                queue_type = item.text(2)

                if not item.isHidden():
                    if queue_type == "SERVER":
                        print "[!] There already exists a server object, delete it to add a new one."
                        return 

	    #If this isn't windows32, this will fail. So let's initialize pypath
	    pypath = ''
            if sys.platform == 'win32':
                pypath = self.options['pypath_win32']
            elif sys.platform == 'darwin' or sys.platform == 'linux':
                # XXX: not tested
                pypath = self.options['pypath_linux']

            server = self.options['toolbag_dir'] + os.sep + "server.py"
            print "[*] Setting up Server queue"
            try:
                # i am 12 and what is this?
                self.myhost = toolbagcomm.ToolbagHost(pypath, server, host, port, key)
            except Exception as detail:
                print detail
                return

            item = QtGui.QTreeWidgetItem(self.queueList)
            item.setText(0, "%s" % host)
            item.setText(1, "")
            item.setText(2, "SERVER")
            item.setText(3, "")

            self.queueServer = item

            self.timer2 = timercallback_t2(self)

        elif self.peerRadio.isChecked():

            try:
                xxx = self.myhost.proc
            except:
                print "[!] You must add a server before adding a peer!"
                return

            try:
                peer_id = self.myhost.addPeer(host, port, key)

                # send a greeting to the peer
                user = getpass.getuser()
                self.myhost.sendPeer("User '%s' subscribed to your queue." % user, "greeting", "greetz.txt", params=None, idx=peer_id)

                self.peers.append(peer_id)
            except Exception as detail:
                print detail
                return

            item = QtGui.QTreeWidgetItem(self.queueList)
            item.setText(0, "%s" % host)
            item.setText(1, "%d" % port)
            item.setText(2, "PEER")
            item.setText(3, "")

            print "[*] Added a peer at %s" % host

        elif self.agentRadio.isChecked():
            try:
                xxx = self.myhost.proc
            except:
                print "[!] You must add a server before adding an agent!"
                return

            try:
                #socket.setdefaulttimeout(2)
                socket.setdefaulttimeout(None)
                self.myhost.addAgent(host, port, key)
                print "[*] Sending agent a greeting"
                self.myhost.agent.connect()
                self.myhost.agent.printmsg("Toolbag Connected")

            except Exception as detail:
                print detail
                socket.setdefaulttimeout(None)
                return

            item = QtGui.QTreeWidgetItem(self.queueList)
            item.setText(0, "%s" % host)
            item.setText(1, "%d" % port)
            item.setText(2, "AGENT")
            item.setText(3, "")

            print "[*] Added an agent at %s" % host


    def OnClose(self, form):
        if self.options['dev_mode']:
            print "[D] OnClose: printing stack:"
            traceback.print_stack()
            
        try:
            comment_dict = pickle.loads(self.fs.load("default.cmts"))
        except:
            comment_dict = {}

        self.fs.store("default.cmts", pickle.dumps(comment_dict))

        try:
            rcomment_dict = pickle.loads(self.fs.load("default.rcmts"))
        except:
            rcomment_dict = {}

        self.fs.store("default.rcmts", pickle.dumps(rcomment_dict))

        # store the master graph
        fh = open(self.options['full_file_name'], 'wb')
        pickle.dump(self.master, fh)
        fh.close()

        try:
            if self.provider.__module__ == "toolbag.providers.ida":
                self.provider.unregisterTimer(self.timer1.obj)
                self.provider.unregisterTimer(self.timer2.obj)
                del self.timer1
        except AttributeError:
            pass

        print "[*] Timer objects deleted"

        socket.setdefaulttimeout(0.5)

        try:
            self.myhost.end()
            print "[*] Server object deleted"
        except Exception as detail:
            pass

        try:
            del self.myhost
        except:
            pass

        # save the default.sess
        self.saveHistory(default=True)

        # close the database
        #self.db.close()

        # delete objects that could cause IDA to crash
        #del(self.db)
        del(self.fs)
        del(self.reftree)

        # delete any Query objects we created
        # prevents IDA from crashing due to a dangling reference
        '''
        for c in self.new_windows:
            try:
                del(c)
            except:
                pass
        '''
        # remove the UI hooks
        self.ui_hook.unhook()
        #del self.ui_hook

        print "[*] Toolbag has been shut down"


    def timerthing(self):
        if self.options['dev_mode']:
            print "[D] timerthing: printing stack:"
            traceback.print_stack()
            
        self.timer1 = timercallback_t([self.refreshMarks, self.refreshStrings, self.refreshImports, self.refreshHistory])


    def deleteQueue(self):
        if self.options['dev_mode']:
            print "[D] deleteQueue: printing stack:"
            traceback.print_stack()
            
        selected = self.queueList.selectedItems()[0]

        # "SERVER" or "AGENT"
        queue_type = selected.text(2)

        # if we were asked to delete a server, but there's a peer, deny it
        if queue_type == "SERVER":

            count = self.queueList.topLevelItemCount()
            for i in xrange(0, count):
                item = self.queueList.topLevelItem(i)
                queue_type = item.text(2)

                if not item.isHidden():
                    if queue_type == "PEER":
                        print "[!] There exists a peer object, delete it before deleting the server."
                        self.rightClickMenuActive = False
                        return 
            try:
                socket.setdefaulttimeout(1)
                self.myhost.end()
                print "[*] Server object deleted"
            except Exception as detail:
                pass
            if self.options['verbosity'] > 2:
                print detail

            try:
                del self.myhost
            except:
                pass

            socket.setdefaulttimeout(None)


        elif queue_type == "AGENT":
           self.myhost.delAgent()

           # except Exception as detail:
           #     print "[!] Failed to delete agent: %s" % detail
           #     return

        # XXX the shadow knows
        selected.setHidden(True)

        self.rightClickMenuActive = False

        return


    def rejectQueueData(self):
        if self.options['dev_mode']:
            print "[D] rejectQueueData: printing stack:"
            traceback.print_stack()
            
        try:
            selected_id = self.queueList.selectedItems()[0].text(3)
        except:
            print "[!] No file selected"
            self.rightClickMenuActive = False
            return 

        item = self.peerdata.fetchitem(int(selected_id))
        objname = self.peerdata.fetchattr(item, "objname")
        objtype = self.peerdata.fetchattr(item, "objtype")
        msg = self.peerdata.fetchattr(item, "data")

        self.queueList.selectedItems()[0].setHidden(True)
        #self.queueList.removeItemWidget(self.queueList.selectedItems()[0], 0)

        self.rightClickMenuActive = False

        self.refreshFilesystem()
        
        self.peerdata.remove(msg)


    def saveQueueData(self):
        if self.options['dev_mode']:
            print "[D] saveQueueData: printing stack:"
            traceback.print_stack()
            
        try:
            selected_id = self.queueList.selectedItems()[0].text(3)
        except:
            print "[!] No file selected"
            self.rightClickMenuActive = False
            return 

        item = self.peerdata.fetchitem(int(selected_id))
        objname = self.peerdata.fetchattr(item, "objname")
        objtype = self.peerdata.fetchattr(item, "objtype")
        msg = self.peerdata.fetchattr(item, "data")

        fname, ok = QtGui.QInputDialog().getText(None, "Store Object", "Enter filename:", QtGui.QLineEdit.Normal, objname)

        if fname == None or not ok:
            self.rightClickMenuActive = False
            return

        print "[*] Storing %s of type %s" % (objname, objtype)

        if objtype == "reftree":
            addys = pickle.loads(msg)
            to_pickle = RefTree.RefTree(masterGraph=self.master, function_data=addys)
            print "[*] Created RefTree from queue data"

            tmp = tempfile.TemporaryFile(mode='wb')
            tmpname = tmp.name
            tmp.close()

            pickled_file = open(tmpname, "wb")
            pickle.dump(to_pickle, pickled_file)
            pickled_file.close()

            fh = open(tmpname, "rb")
            obj_data = fh.read()
            fh.close()

        elif objtype == "marks":
            #self.sendPeer((marks, group), "marks", "marks.marks")
            marks,groups = pickle.loads(msg)

            '''
            for mark_ea, mark in marks.iteritems():
                self.db.tag(mark_ea, 'mark', mark['mark'])

            self.refreshMarks(self.db)
            '''

            obj_data = msg

            '''
            if len(groups) == 0:
                self.db_obj.tag(ea, 'mark', description)
            else:
                self.db_obj.tag(ea, 'mark', description)
                self.db_obj.tag(ea, 'group', group)
            '''

        elif objtype == "agentresults":
           obj_data = msg 

        # otherwise just pickle the object to disk
        else:
            obj_data = msg

        self.queueList.selectedItems()[0].setHidden(True)
        #self.queueList.removeItemWidget(self.queueList.selectedItems()[0], 0)

        self.fs.store(fname, obj_data)

        self.rightClickMenuActive = False

        self.refreshFilesystem()

        self.peerdata.remove(msg)


    def pullQueueData(self, shiftfocus=True):
        if self.options['dev_mode']:
            print "[D] pullQueueData: printing stack:"
            traceback.print_stack()
            
        print "[*] Pulling data from the queue"
    
        if shiftfocus:
            try:
                self.tabs.setCurrentWidget(self.queueTab)
            except Exception as detail:
                print detail
        

        try:
            socket.setdefaulttimeout(3)
            networkdata = self.myhost.recv()
            pkt = toolbagcomm.ToolbagPacket(networkdata)
            socket.setdefaulttimeout(None)
            
            if pkt.opcode == "greeting":
                self.showBalloon("%s (%s)" % (pkt.msg, pkt.ip), clickable=False)
                return

            #racksonracksonracks
            elif pkt.opcode == "agentresults":
                self.showBalloon("Agent results for %s" % pkt.filename, clickable=False)
                self.global_hook.retvals[pkt.filename]=pickle.loads(pkt.msg)
                return

            # IP : objname, objtype, data
            new_id = self.peerdata.newid()
            self.peerdata.add(pkt.ip, pkt.filename, pkt.opcode, pkt.msg, new_id)

            peer_data_widget = QtGui.QTreeWidgetItem(self.queueServer)
            peer_data_widget.setExpanded(True)
            self.queueServer.setExpanded(True)
            peer_data_widget.setText(0, "%s" % pkt.ip)
            peer_data_widget.setText(1, "%s" % pkt.filename)
            peer_data_widget.setText(2, "%s" % pkt.opcode)
            peer_data_widget.setText(3, "%d" % new_id)

        except Exception as detail:
            print detail
            raise
            return


    def showBalloon(self, msg, clickable=True):
        if self.options['dev_mode']:
            print "[D] showBalloon: printing stack:"
            traceback.print_stack()
            
        self.message = QtGui.QSystemTrayIcon()
        self.message.show()
        self.message.showMessage("IDA Pro - Toolbag", msg, msecs=5000)
        if clickable:
            self.pullQueueData(shiftfocus=False)
            # removing the need to click the balloon
            #self.message.messageClicked.connect(self.pullQueueData)


    def get_refcounts(self):
        if self.options['dev_mode']:
            print "[D] get_refcounts: printing stack:"
            traceback.print_stack()
            
        import types
        d = {}
        sys.modules
        # collect all classes
        for m in sys.modules.values():
            for sym in dir(m):
                o = getattr (m, sym)
                if type(o) is types.ClassType:
                    d[o] = sys.getrefcount (o)

                    for sym in dir(o):
                        ox = getattr(o, sym)
                        if type(ox) is types.ClassType:
                            d[ox] = sys.getrefcount(ox)
        # sort by refcount
        pairs = map (lambda x: (x[1],x[0]), d.items())
        pairs.sort()
        pairs.reverse()
        return pairs


###############################################################################

class timercallback_t(object):
    def __init__(self, funcptrs):
        self.funcptrs = funcptrs
        self.provider = ida.IDA()
        
        self.interval = 1000

        if self.provider.__module__ == "toolbag.providers.ida":
            self.obj = self.provider.registerTimer(self.interval, self)
        
        if self.obj is None:
            raise RuntimeError, "Failed to register timer"

    def __call__(self):

        # removing, because if you have enough global marks to necessitate a scrollbar, 
        # when this fires it will scroll that back to the top, which is annoying
        for ptr in self.funcptrs:
            ptr(local=True)
        return self.interval

    def __del__(self):
        print("Timer object disposed %s" % id(self))


class timercallback_t2(object):
    def __init__(self, ui_obj):
        self.ui_obj = ui_obj
        self.provider = ida.IDA()

        self.msgshown = 0
        self.interval = self.ui_obj.options['queue_interval']

        if self.provider.__module__ == "toolbag.providers.ida":
            self.obj = self.provider.registerTimer(self.interval, self)

        if self.obj is None:
            raise RuntimeError, "Failed to register timer"

    def __call__(self):
        try:
            x = None
            try:
                x = self.ui_obj.myhost.poll()
            except Exception as detail:
                print "[!] It appears a server went down, %s" % detail
                socket.setdefaulttimeout(1)
                self.ui_obj.myhost = None
                return 0

                # XXX: remove it from the UI

            if x != None and x != False:
                socket.setdefaulttimeout(None)

                # only show the message every 10*interval
                if self.msgshown % self.ui_obj.options['queue_reminder'] == 0:

                    print "[*] Data in the queue"

                    try:
                        if self.msgshown != 0:
                            self.ui_obj.showBalloon("There is still pending data in the queue")
                        else:
                            self.ui_obj.showBalloon("Received data in the queue")
                    except Exception as detail:
                        print "Failed showing balloon: %s" % detail

                self.msgshown += 1
                
            else:
                self.msgshown = 0

        except Exception as detail:
            print detail
            #raise Exception

        return self.interval

    def __del__(self):
        print("Timer object disposed %s" % id(self))
