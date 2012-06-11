# fs.py
#
# for public release, 2012
#
# Aaron Portnoy

# Standard Libraries
import sys
import copy
from zipfile import *
from StringIO import StringIO

# IDA
import idaapi
import idautils

#
import segment

# IDA provider
from providers import ida

class FS:
    '''
    File system object
        - default size of ~2MB
    '''

    def __init__(self, options):
        self.segname = options['segment_name']
        self.size    = options['segment_size'] 
        self.provider = ida.IDA()
        self.memhandle = StringIO()

        done = False
        # (name, start, end)
        segs = segment.getSegsInfo()
        for s in segs:

            # if our segment is already present, use it
            if self.segname == s[0]:
                print "[*] fs.py: found an existing segment, using it."

                # start address
                self.addr = s[1]

                eof = self.get_eof()

                if eof == 0:
                    done = True
                    break

                # the EOF is the first 4 bytes
                # seek to the actual data
                ea = self.addr + 4

                # get the data
                bytes = ""
                for i in xrange(0, eof):
                    bytes += chr(self.provider.getByte(ea))
                    ea += 1

                
                self.memhandle.write(bytes)
                self.memhandle.seek(0)

                # save the new size
                self.EOF = len(bytes)
                self.save_eof()
                done = True
                break

        # otherwise, make a new one
        if done == False:
            print "[*] fs.py: didn't find an existing segment, making a new one."
            self.addr = segment.alloc(self.size, self.segname)
            self.EOF = 0
            self.save_eof()
            

        zipfs = ZipFile(self.memhandle, mode='w')
        zipfs.close()
        self.memhandle.seek(0)


    def list_files(self):
        zipfs = ZipFile(self.memhandle, mode='r')
        names = zipfs.namelist()
        zipfs.close()

        return names


    def get_fh(self):
        fh = StringIO()

        return fh

    def store_fh(self, fh, name):
        fh.seek(0)
        self.store(name, fh.read())
        
        return True
    

    def get_current_size(self):
        '''Returns the amount of bytes currently stored in the fs segment'''
        size = 0
        ea = self.addr

        return self.get_eof()


    def store(self, k, v):
        '''Stores a file (named k) with value (v) in the segment. Directory paths are allowed.'''

        try:
            names = self.list_files()
        except BadZipfile:
            names = []
            pass

        if k in names:
            print '[!] fs.py: Found file with name %s, replacing it as requested' % k 
            self.delete(k)

        zipfs = ZipFile(self.memhandle, mode='a')

        current_size = self.get_current_size()
        len_data = len(v)

        total_size = current_size + len_data
        
        # need to check if our current segment can contain total_size

        our_seg = self.provider.segByName(self.segname)

        # this is because IDA doesnt delete segments properly (selectors are gay)
        segs = list(self.provider.getSegments())
        for s in segs:
            name = self.provider.segName(s)
            if name == self.segname:
                our_seg = s
                break

        if our_seg == 0xFFFFFFFF:
            raise SyntaxError("Hrm, segment is BADADDR")

        our_seg_size = self.provider.segEnd(our_seg) - self.provider.segStart(our_seg)

        if total_size > our_seg_size:
            raise
            # we need to resize our segment
            new_seg = segment.realloc(our_seg, total_size)
            self.addr = new_seg
        
        print '[*] Adding file %s to keystore (len:%d)' % (k, len(v))
        zipfs.writestr(k, v)
        zipfs.close()
        self.memhandle.seek(0)
        self.commit()

        return True


    def load(self, k):
        '''Retrieves the contents of a file (named k) from the segment file system.'''
        try:
            zipfs = ZipFile(self.memhandle, mode='r')
        except:
            return False

        try:
            zfile = zipfs.open(k)
            res = zfile.read()
        except KeyError:
            #print "[!] File with name '%s' does not exist in the keystore." % k
            return False

        self.memhandle.seek(0)

        return res


    def delete(self, k):
        tmphandle = StringIO()
        try:
            zin = ZipFile(self.memhandle, mode='r')
        except:
            print self.memhandle.read()

        zout = ZipFile(tmphandle, mode='w')

        deleted = False
        for item in zin.infolist():
            if item.filename != k:
                buffer = zin.read(item.filename)
                zout.writestr(item, buffer)
            else:
                print "[*] Deleting file '%s' from keystore." % k
                deleted = True

        if deleted == False:
            print "[*] File '%s' does not exist within keystore." % k
        
        zin.close()
        zout.close()    
        self.memhandle = copy.deepcopy(tmphandle)
        self.memhandle.seek(0)
        self.commit()


    def save_eof(self):
        #print "[*] Saving EOF at address 0x%08x" % self.addr
        ea = self.addr
        self.provider.patchDword(ea, self.EOF)

        return


    def get_eof(self):
        ea = self.addr

        return self.provider.getDword(ea)


    def commit(self):
        '''Commits any changes made to the in-memory buffer to the segment. This is automatically invoked on any store() or delete() operation.'''
        bytes = self.memhandle.read()
        self.memhandle.seek(0)

        ea = self.addr

        # write the EOF
        self.EOF = len(bytes)
        self.save_eof()

        ea = ea+4

        for byte in bytes:
            self.provider.patchByte(ea, ord(byte))
            ea = ea + 1


    def gimme_zip(self):
        '''This is a utility function for testing purposes. It returns all the data currently stored in the segment (it should be a zip file)'''
        eof = self.get_eof()
        self.memhandle.seek(0)

        res = ""

        # seek past EOF
        ea = self.addr+4

        for i in xrange(0, eof):
            res += chr(self.provider.getByte(ea))
            ea = ea + 1

        return res