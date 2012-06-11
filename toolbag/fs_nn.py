# fs.py
#
# for public release, 2012
#
# Aaron Portnoy

# Standard Libraries
import sys
import copy
import pickle
from zipfile import *
from StringIO import StringIO

# IDA
import idc
import idaapi
import idautils

#
import segment


class FS:
    '''
    File system object

    I'm pretty sure I'm not using netnodes the proper way. 
    I'm pretty sure I'm limited to 255 files because of this.

    I'll read the hpp sometime...
    '''

    def __init__(self, options):
        # self.files is a dict() mapping {filename: tag}
        self.num = options['netnode_num']
        self.nnode = idaapi.netnode(self.num)

        # check if we already have an existing files dict() defined
        if self.nnode.getblob(0, "\x01"):
            # if we do, set self.files to it
            self.files = pickle.loads(self.nnode.getblob(0, "\x01"))            
        else:
            # otherwise set it to a dict containing just the \x01 tag reserved
            self.files = {"__internal__" : "\x01"}
            self.nnode.setblob(pickle.dumps(self.files), 0, "\x01")

        self.used = self.files.values()

        return


    def list_files(self):
        files = pickle.loads(self.nnode.getblob(0, "\x01"))
        return files.keys()
        

    def next_index(self):

        possible_vals = []
        for i in xrange(2, 256):
            possible_vals.append(chr(i))

        for x in possible_vals:
            if x not in self.used:
                return x

        raise Exception, "WTFMATE"


    def store(self, k, v):
        '''Stores a file (named k) with value (v) in the netnode.'''

        files = pickle.loads(self.nnode.getblob(0, "\x01"))

        names = files.keys()[1:]

        if k in names:
            print '[!] Found file with name %s, replacing it as requested' % k 
            self.delete(k)

        print '[*] Adding file %s to keystore (len:%d)' % (k, len(v))

        next_idx = self.next_index()
       
        files[k] = next_idx

        self.nnode.setblob(v, 0, next_idx)
        self.used.append(next_idx)
        self.nnode.setblob(pickle.dumps(files), 0, "\x01")

        return True


    def store_fh(self, fh, name):
        fh.seek(0)
        self.store(name, fh.read())

        return True


    def load(self, k):
        '''Retrieves the contents of a file (named k) from the netnodesphere.'''
        
        files = pickle.loads(self.nnode.getblob(0, "\x01"))

        try:
            return self.nnode.getblob(0, files[k])
        except KeyError:
            #print "[!] File with name '%s' does not exist in the netnodesphere." % k
            return False


    def delete(self, k):
        files = pickle.loads(self.nnode.getblob(0, "\x01"))        
        
        idx = files[k]
        
        res = self.nnode.delblob(0, idx)
        
        if res:
            print "[*] Deleting file '%s' from keystore." % k
            del files[k]
            self.nnode.setblob(pickle.dumps(files), 0, "\x01")
        else:
            print "[*] File '%s' does not exist within keystore." % k
        
