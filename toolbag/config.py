# config.py
#
# for public release, 2012
#
# Aaron Portnoy

import os

import idc
import idaapi

user = False
try:
    import userconfig
    user = True
except Exception as detail:
    print '[!] Failed to load userconfig.py. Resorting to default toolbag options, %s' % detail


# for colors, see: # http://www.w3.org/TR/SVG/types.html#ColorKeywords
options = { 
                # Supported options: disk (remote only in private release)
                'db_location'            : 'disk',

                # python
                'pypath_win32'           : 'C:\\Python26\\python.exe',
                # XXX: not tested
                'pypath_linux'           : '/usr/bin/env python',

                # default tabs enabled
                'enabled_tabs'           : ["File System", "Pathfinding", "Scripts"],

                # local comments or marks
                # valid values: 'marks' or 'comments'
                'localview'              : 'comments',

                # show splash boolean
                'show_splash'            : True,

                # architecture
                'architecture'           : (lambda: idc.__EA64__ and "64" or "32")(),

                # filesystem options
                # valid options are 'netnode' or 'segment'
                'file_system_type'       : 'netnode',
                'netnode_num'            : 0xBEEFFACE,

                'segment_size'           : 0x200000,
                'segment_name'           : '.zip',
                'file_name'              : idaapi.get_root_filename()[:-4] + ".DB",
                'full_file_name'         : (lambda x: "." in x and x.split(".")[0] + ".DB" or x + ".DB")(idaapi.get_root_filename()),
    
                'ida_user_dir'           : idaapi.get_user_idadir(),
                'user_scripts_dir'       : idaapi.get_user_idadir() + os.sep + "user" + os.sep + "bin",
                'vtrace_scripts_dir'     : idaapi.get_user_idadir() + os.sep + "user" + os.sep + "bin" + os.sep + "vtrace",
                'toolbag_dir'            : idaapi.get_user_idadir() + os.sep + "toolbag",
                    
                # hotkeys     
                'history_hotkey'         : 'Ctrl-Space',
                'undo_history'           : 'Ctrl-Z', 
                'create_mark_hotkey'     : 'Alt-M',
                'jump_mark_hotkey'       : 'Ctrl-M',
                'path_start'             : 'Ctrl-S',
                'path_end'               : 'Ctrl-E', 
                'add_edge_src'           : 'Ctrl-[',
                'add_edge_dst'           : 'Ctrl-]',

                # these two are currently deprecated, ScreenEA() is used
                'bb_path_start'          : 'Ctrl-Shift-S',
                'bb_path_end'            : 'Ctrl-Shift-E',
                    
                # aesthetics    
                'font_name'              : 'Courier',
                'font_size'              : 8,
                'font_color'             : 'black',
                'background_color'       : 'gainsboro',

                # for use with the 'Query DB' searching functionality
                'highlighted_background' : 'darkgreen',
                'highlighted_foreground' : 'white',
    
                # IDA only accepts RGB values
                'history_color'          : 0x005500,
                'coloring_enabled'       : False,
    
                # path finding colors (RGB again)  
                'path_coloring_enabled'  : False,
                'func_path_color'        : 0xFF00FF,
                'bb_path_color'          : 0x0000FF,
    
                'editor'                 : 'C:\\windows\\system32\\notepad.exe',
                #'editor'                : '/usr/bin/vim'

                # not currently used
                'remote_host'            : '192.168.1.100',

                # milliseconds to poll queue
                'queue_interval'         : 1500,

                # queue_interval * this = how often you'll get reminded about pending data
                'queue_reminder'         : 6,
    
                # dev-mode    
                'dev_mode'               : False,

                # 1,2,3
                'verbosity'              : 2
          }
    


if user == True: 
    try:
        for k,v in userconfig.options.iteritems():
            options[k] = v
    except AttributeError as detail:
        print '[!] Error overriding global options with userconfig options, %s' % detail
