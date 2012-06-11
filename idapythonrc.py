# __init__.py
#
# for public release, 2012
#
#

import sys,os
import idc,idautils,idaapi

from PySide import QtGui as QtGui

# store the root path
import __root__
root = __root__.__file__[ : __root__.__file__.rfind(os.sep) ]

# add subdirs to the search path
# XXX: we might be able to do this via the ihooka module
for h in ['base','app', 'misc', 'user', r'toolbag', r'toolbag%smisc' % os.sep, r'toolbag%sproviders' % os.sep, r'toolbag%sagent%sdbg' % (os.sep, os.sep), r'toolbag%sagent' % os.sep]:
    sys.path.append('%s%c%s'% (root, os.sep, h))

# import the default modules
import comment,database,segment,function
import instruction

# shortcuts
(db,fn) = (database,function)
h,go,top = (db.h, db.go, lambda:fn.top(db.h()))
hex = lambda i: '%x'% i

# try and execute our user's idapythonrc.py
try:
    if (os.getenv('HOME') and os.path.exists('%s%cidapythonrc.py'% (os.getenv('HOME'), os.sep))):
        execfile( '%s%cidapythonrc.py'% (os.getenv('HOME'), os.sep) )
    elif (os.getenv('USERPROFILE') and os.path.exists('%s%cidapythonrc.py'% (os.getenv('USERPROFILE'), os.sep)) ):
        execfile( '%s%cidapythonrc.py'% (os.getenv('USERPROFILE'), os.sep) )
    elif (os.getenv('USERPROFILE') and os.path.exists('%s%c_idapythonrc.py'% (os.getenv('USERPROFILE'), os.sep)) ):
        execfile( '%s%c_idapythonrc.py'% (os.getenv('USERPROFILE'), os.sep) )
    elif (os.getenv('USERNAME') and os.path.exists('%s%suser%s%s.py' % (root, os.sep, os.sep, os.getenv('USERNAME').lower()) ) ):
        execfile( '%s%suser%s%s.py'% (root, os.sep, os.sep, os.getenv('USERNAME').lower()) )
    else:
        print '[!] Unable to load idapythonrc.py from the user\'s home directory'
    pass
except IOError:
    print 'warning: No idapythonrc.py file found in home directory'

except Exception, e:
    print 'warning: Exception %s raised'% repr(e)
    import traceback
#    tb = traceback.format_stack()
#    print ''.join(tb)
    traceback.print_exc()
