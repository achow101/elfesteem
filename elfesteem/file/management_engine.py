# ME syntax: firmware for Intel Management Engine

# The main source of information on this format are
#   http://me.bios.io/ME_blob_format
#   https://github.com/zamaudio/dump_me
#   https://github.com/skochinsky/me-tools
#   http://io.netgarage.org/me/ especially unhuffme

import struct
from elfesteem.cstruct import CBase, CData, CStruct, CArray, data_null, data_empty
from elfesteem.strpatchwork import StrPatchwork

from elfesteem.core.cell import *

class Header(CStruct):
    # Same names as https://github.com/zamaudio/dump_me/blob/master/dump_me.py
    _fields = [ ("Magic","4s"),
                ("NumEntries","u32"),
                ("Version","u08"),
                ("EntryType","u08"),
                ("HeaderLen","u08"),
                ("Checksum","u08"),
                ("FlashCycleLifetime","u16"),
                ("FlashCycleLimit","u16"),
                ("UMASize","u32"),
                ("Flags","u32"),
                ("unknown","8s"),
              ]
    _display = {
               "Version": lambda self: "%d.%d" % (self.Version >> 4, self.Version & 0xF),
               "EntryType": "#04x",
               "HeaderLen": "#04x",
               "Checksum": "#04x",
               "Flags": "#010x",
               }


class FptEntry(CStruct):
    # Same names as https://github.com/zamaudio/dump_me/blob/master/dump_me.py
    _fields = [ ("Name","4s"),
                ("Owner","4s"),
                ("Offset","u32"),
                ("Size","u32"),
                ("TokensOnStart","u32"),
                ("MaxTokens","u32"),
                ("ScratchSectors","u32"),
                ("Flags","u32"),
              ]
    _display = { "Flags": "#x" }

class PartitionTable(CArray):
    _cls = FptEntry
    count = lambda _: _.parent.hdr.NumEntries

"""
# NB: the following definition is taken from
# https://github.com/ohadbc/sysbios-rpmsg/blob/master/src/utils/rprcfmt.h
# It does not correspond to the RPRC files we have
class ResourceNewABI(CStruct):
    _fields = [ ("type","u32"),
                ("id","u32"),
                ("da","u64"),   # Device Address
                ("pa","u64"),   # Physical Address
                ("len","u32"),
                ("flags","u32"),
                ("reserved","16s"),
                ("name","48s"),
                ]

class Resource(CStruct):
    _fields = [ ("type","u32"),
                ("da","u64"),   # Device Address
                ("pa","u64"),   # Physical Address
                ("len","u32"),
                ("flags","u32"),
                ("name","48s"),
                ]
    name_txt = property(lambda _:_.name.strip(data_null).decode('latin1'))
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        self.offset = o
    def display(self):
        return 'resource %(type)d, da: %(da)#010x, pa: %(pa)#010x, len: %(len)#010x, name: %(name_txt)s' % self

class Section(CStruct):
    _fields = [ ("type","u32"),
                ("da","u64"),   # Device Address
                ("len","u32"),
                ("data",CData(lambda _:_.len))]
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        self.offset = o
        if self.type == FW_RESOURCE:
            self.res_len = Resource(parent=self).bytelen
            if self.data.bytelen % self.res_len != 0:
                raise ValueError('Section data length %#x not multiple of %#x' % (self.data.bytelen, self.res_len))
            of = 0
            self.res = []
            while of + self.res_len <= self.data.bytelen:
                r = Resource(parent=self, content=self.data, start=of)
                self.res.append(r)
                of += self.res_len
    def display(self):
        rep = []
        rep.append('section %(type)d, address: %(da)#010x, size: %(len)#010x' % self)
        if self.type == FW_RESOURCE:
            rep.append('resource table: %d' % self.res_len)
            for r in self.res:
                rep.append(r.display())
        return '\n'.join(rep)
    def __str__(self):
        return 'section %(type)d, address: %(da)#010x, size: %(len)#010x' % self
"""

class Layout(object):
    ''' This class manages the layout of the file when loaded in memory. '''
    def __init__(self, overlap=None):
        ''' Initialize with an empty memory '''
        if   overlap == 'silent':
            pass
        elif overlap == 'warning':
            TODO
        elif overlap == 'error':
            TODO
        else:
            raise ValueError('Define overlap in %s'%self.__class__)
        self.layout = [(0, None)]
    def __setitem__(self, item, data):
        ''' Load 'data' in memory at interval 'item'. '''
        if item.start == item.stop:
            return
        # Find the position in the layout where the data is loaded
        for i, (o, _) in enumerate(self.layout):
            if o >= item.start: break
        else:
            i = len(self.layout)
        # Find the position in the layout where the data loading ends
        for j, (o, _) in enumerate(self.layout):
            if o > item.stop: break
        else:
            j = len(self.layout)
        # Find what is the value after the end
        _, prv_data = self.layout[j-1]
        self.layout[i:j] = [(item.start, data),(item.stop, prv_data)]
    def __getitem__(self, item):
        ''' Return a list of (slice, data) which indicates what is in
            memory at interval 'item'; the slices that are returned
            are contiguous and add up to the whole 'item' slice. '''
        res = []
        for i, (stop, _) in enumerate(self.layout):
            if item.start >= stop:
                continue
            start, data = self.layout[i-1]
            if item.stop <= start:
                continue
            res.append((slice(max(item.start,start),min(item.stop,stop)),data))
        if stop < item.stop:
            _, data = self.layout[-1]
            res.append((slice(stop,item.stop),data))
        return res
    def max_addr(self):
        return self.layout[-1][0]

class Virtual(object):
    # This class manages 'virtual addresses', i.e. the addresses when
    # the RPRC file is loaded in memory.
    # These addresses are the ones used by absolute addressing in the
    # executable code.
    def __init__(self, e):
        self.parent = e
        self.layout = Layout(overlap='silent')
        for s in self.parent.sections:
            self.layout[s.da:s.da+s.len] = s
    def __getitem__(self, item):
        # If 'item' is an integer, we return the byte at this address,
        # else 'item' is a slice and we return the corresponding bytes,
        # padded with zeroes.
        if type(item) is slice:
            assert item.step is None
            start, stop = item.start, item.stop
        else:
            start, stop = item, item+1
        res = data_empty
        for i, s in self.layout[start:stop]:
            if s is None: res += data_null * (i.stop-i.start) # non-mapped
            else: res += s.data[i.start-s.da:i.stop-s.da]
        return res
    def __setitem__(self, item, data):
        # If 'item' is an integer, we write starting from this address
        if type(item) is slice:
            assert item.step is None
            start, stop = item.start, item.stop
            assert len(data) == stop-start
        else:
            start, stop = item, item+len(data)
        l = self.layout[start:stop]
        if None in [ s for _, s in l]:
            raise ValueError('Addresses %#x:%#x not entirely mapped in memory'%(start,stop))
        for i, s in l:
            of = i.start-start
            s.data[i.start-s.da:i.stop-s.da] = data[i.start-s.da+of:i.stop-s.da+of]
    def max_addr(self):
        return self.layout.max_addr()

class ME(object):
    # API shared by all/most binary containers
    #architecture = property(lambda _:'ARM')
    #entrypoint = property(lambda _:-1)
    #sections = property(lambda _:_.SHList.shlist)
    #symbols = property(lambda _:())
    #dynsyms = property(lambda _:())

    sex = '<'
    wsize = 32
    virt = property(lambda _:_._virt)
    def __init__(self, data = None, **kargs):
        self.sections = []
        if data is not None:
            self.content = StrPatchwork(data)
            self.parse_content()
        else:
            TODO
        self._virt = Virtual(self)
    def parse_content(self):
        # First step
        log.setLevel(logging.DEBUG)
        data = str(self.content)
        of = 0
        """
        self.hdr = Header()
        print(repr(self.hdr))
        try:
            self.hdr = Header(data, offset=of)
        except CellParsingError:
            # There might be 16 bytes of padding. Accordinf to
            # https://github.com/zamaudio/dump_me/blob/master/dump_me.py
            # it is not always the case.
            of += 16
            self.hdr = Header(data, offset=of)
        self.padding = self.content[:of]
        return
        """
        
        self.hdr = Header(parent=self, content=self.content, start=of)
        if str(self.hdr.Magic) != '$FPT':
            # There might be 16 bytes of padding. Accordinf to
            # https://github.com/zamaudio/dump_me/blob/master/dump_me.py
            # it is not always the case.
            of += 16
            self.hdr = Header(parent=self, content=self.content, start=of)
        if str(self.hdr.Magic) != '$FPT':
            raise ValueError("Not a ME firmware (magic)")
        if int(self.hdr.HeaderLen) != of + self.hdr.bytelen:
            raise ValueError("Not a ME firmware (len)")
        self.padding = self.content[:of]
        of += self.hdr.bytelen
        self.fpt = PartitionTable(parent=self, content=self.content, start=of)
        """
        of = self.hdr.bytelen
        while of < len(self.content):
            s = Section(parent=self, content=self.content, start=of)
            self.sections.append(s)
            of += s.bytelen
        """
    def pack(self):
        """
        c = StrPatchwork()
        c[0] = self.hdr.pack()
        of = self.hdr.bytelen
        for s in self.sections:
            c[of] = s.pack()
            of += s.bytelen
        return c.pack()
        """
    def display(self):
        # Same output as 'readrprc'
        rep = ["Initial padding %r" % self.padding,
              self.hdr.display()
          ] + ["Partition no %d\n" % i + s.display()
               for i, s in enumerate(self.fpt)
          ]
        return '\n'.join(rep)
    def getsectionbyvad(self, ad):
        """
        # Same API as ELF or PE, but different implementation for accessing
        # data by virtual addresses: a mechanism entirely inside 'virt'
        # rather than split between two classes; future versions of
        # elfesteem should probably do the same for all binary containers.
        return self.virt.layout[ad:ad+1][0][1]
        """







class FptHeader(AttributesElfesteem,Struct):
    # Same names as https://github.com/zamaudio/dump_me/blob/master/dump_me.py
    _fields = [
        ("Magic",              Str[4]        .fixed("$FPT")),
        ("NumEntries",         Int),
        ("Version",            Byte          .default(2)),
        ("EntryType",          Byte),
        ("HeaderLen",          Byte),
        ("Checksum",           Byte),
        ("FlashCycleLifetime", Short),
        ("FlashCycleLimit",    Short),
        ("UMASize",            Int),
        ("Flags",              Int),
        ("unknown",            Str[8]),
        ]
    def display(self):
        # Same as https://github.com/zamaudio/dump_me/blob/master/dump_me.py
        res = [ "===ME Flash Partition Table===" ]
        res.append( "NumEntries: %d" % self.NumEntries )
        res.append( "Version:    %d.%d" % (self.Version >> 4, self.Version & 0xF) )
        res.append( "EntryType:  %02X"  % self.EntryType )
        res.append( "HeaderLen:  %02X"  % self.HeaderLen )
        res.append( "Checksum:   %02X"  % self.Checksum )
        res.append( "FlashCycleLifetime: %d" % self.FlashCycleLifetime )
        res.append( "FlashCycleLimit:    %d" % self.FlashCycleLimit )
        res.append( "UMASize:    %d" % self.UMASize )
        res.append( "Flags:      %08X" % self.Flags )
        res.append( "    EFFS present:   %d" % (self.Flags&1) )
        res.append( "    ME Layout Type: %d" % ((self.Flags>>1)&0xFF) )
        return "\n".join(res)

class FptEntry(AttributesElfesteem,Struct):
    # Same names as https://github.com/zamaudio/dump_me/blob/master/dump_me.py
    _fields = [
        ("Name",           Str[4]),
        ("Owner",          Str[4]),
        ("Offset",         Int),
        ("Size",           Int),
        ("TokensOnStart",  Int),
        ("MaxTokens",      Int),
        ("ScratchSectors", Int),
        ("Flags",          Int),
        ]
    PartTypes = ["Code", "BlockIo", "Nvram", "Generic", "Effs", "Rom"]
    def display(self):
        # Same as https://github.com/zamaudio/dump_me/blob/master/dump_me.py
        res = [ ]
        res.append( "Partition:      %r" % self.Name )
        res.append( "Owner:          %s" % [repr(self.Owner), "(none)"]
                                     [self.Owner == '\xFF\xFF\xFF\xFF'] )
        res.append( "Offset/size:    %08X/%08X" % (self.Offset, self.Size) )
        res.append( "TokensOnStart:  %08X" % self.TokensOnStart )
        res.append( "MaxTokens:      %08X" % self.MaxTokens )
        res.append( "ScratchSectors: %08X" % self.ScratchSectors )
        res.append( "Flags:              %04X" % self.Flags )
        res.append( self.display_flags() )
        return "\n".join(res)
    def display_flags(self):
        # Same as https://github.com/zamaudio/dump_me/blob/master/dump_me.py
        flags = self.Flags
        res = [ ]
        pt = flags & 0x7F
        if pt < len(self.PartTypes):
            stype = "%d (%s)" % (pt, self.PartTypes[pt])
        else:
            stype = "%d" % pt
        res.append( "    Type:         %s" % stype )
        res.append( "    DirectAccess: %d" % ((flags>>7)&1) )
        res.append( "    Read:         %d" % ((flags>>8)&1) )
        res.append( "    Write:        %d" % ((flags>>9)&1) )
        res.append( "    Execute:      %d" % ((flags>>10)&1) )
        res.append( "    Logical:      %d" % ((flags>>11)&1) )
        res.append( "    WOPDisable:   %d" % ((flags>>12)&1) )
        res.append( "    ExclBlockUse: %d" % ((flags>>13)&1) )
        return "\n".join(res)

# These constants could be autogenerated from FptEntry.PartTypes
PT_CODE    = 0
PT_BLOCKIO = 1
PT_NVRAM   = 2
PT_GENERIC = 3
PT_EFFS    = 4
PT_ROM     = 5

class MeFptTable(Struct):
    _fields = [
        ("hdr",           FptHeader),
        ("fpt",           VarArray[FptEntry]),
        ]
    _rules = [
        RuleEqual('hdr.NumEntries', 'fpt.count'),
        ]

class MeFptTableWithPadding(MeFptTable):
    _fields = [ ("padding", Str[16]) ] + MeFptTable._fields

class ME(AttributesElfesteem,Union):
    _options = [ MeFptTable, MeFptTableWithPadding ]
    def display(self):
        # Same as https://github.com/zamaudio/dump_me/blob/master/dump_me.py
        res = [ self['hdr'].display() ]
        res.append("---Partitions---")
        res.extend([_.display() for _ in self['fpt']])
        res.append("------End-------")
        return "\n".join(res)

if __name__ == "__main__":
    import sys, code
    if len(sys.argv) > 2:
        for f in sys.argv[1:]:
            print('File: %s'%f)
            e = ME(open(f, 'rb').read())
            print (e.display())
        sys.exit(0)
    if len(sys.argv) == 2:
        data = open(sys.argv[1], 'rb').read()
        """
        e = ME(data)
        print (e.display())
        # PSVN.KRID, FOVD.KRID, MOES.MDID, ...
        """
        e = Struct[[("padding", Str[16]),
                    ("hdr",     FptHeader),
                    ("fpt",     Array[FptEntry,3]),
                  ]](data)
        #e = MeFptTableWithPadding(data) # OK
        #e = MeFptTable(data) # CellError
        e = ME(data)
        print(e.show())
        print(e.hdr.NumEntries)
        #print(e['hdr'].show())
        #print(e.repr())
        #print(repr(e))
        #print(dir(e.hdr))
        #print(repr(e.hdr))
        #print(repr(e.fpt[0]))
        #print(e.display())
    code.interact('Interactive Python Console', None, locals())
