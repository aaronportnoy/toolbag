
import os
import sys

import PE

'''
For now, all this does is rename files to their exportname and version info.
(more to come is likely)
'''

if __name__ == "__main__":

    for fname in sys.argv[1:]:

        print 'Parsing: %s' % fname

        vsver = None
        expname = None

        pe = PE.peFromFileName(fname)

        expname = pe.getExportName()

        dirname = os.path.dirname(fname)

        vs = pe.getVS_VERSIONINFO()
        if vs == None:
            print 'No VS_VERSIONINFO found!'

        else:
            keys = vs.getVersionKeys()
            keys.sort()
            for k in keys:
                val = vs.getVersionValue(k).encode('ascii','ignore')
                print '%s: %s' % (k, val)

        #if vs != None:
            #vsver = vs.getVersionValue('FileVersion')
            #newpath = os.path.join(dirname, '

        #if vsver != None and expname != None:
            #expname = expname.split('.')[0].lower()
            #vsver = vsver.split()[0]
            #destpath = os.path.join(dirname, '%s_%s.dll' % (expname, vsver))
            #print 'Renaming to %s' % destpath
            #os.rename(sys.argv[1], destpath)

