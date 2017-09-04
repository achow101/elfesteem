#! /usr/bin/env python

from elfesteem.core.cell import *
from elfesteem.core.scapy import *

def load_proto(constants, filename):
    import logging
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
    log = logging.getLogger("scapy_loading")
    log.setLevel(logging.INFO)
    log.addHandler(handler)
    """ Parser taken from scapy2. """
    import re
    spaces = re.compile("[ \t]+|\n")
    try:
        for l in open(filename):
            try:
                shrp = l.find("#")
                if  shrp >= 0:
                    l = l[:shrp]
                l = l.strip()
                if not l:
                    continue
                lt = tuple(re.split(spaces, l))
                if len(lt) < 2 or not lt[0]:
                    continue
                constants.extend(int(lt[1]), lt[0])
            except:
                e = sys.exc_info()[1]
                log.info("Couldn't parse file [%s]: line [%r] (%s)"
                        % (filename, l, e))
    except IOError:
        log.info("Can't open %s file" % filename)

PROTO_NAMES = NamedConstants((
    # Hardwrite the most common types, in case /etc/protocols is missing
    ( 0, 'ip'),
    ( 1, 'icmp'),
    ( 2, 'igmp'),
    ( 6, 'tcp'),
    (17, 'udp'),
    ))
load_proto(PROTO_NAMES, '/etc/protocols')

class HexShort(Short):
    def work2repr(self, val):
        if val is not None:
            val = hex(val)
        return val

def checksum(data):
        if len(data) % 2 == 1:
            data += struct.pack('B',0)
        import array
        s = sum(array.array("H", data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        if struct.unpack("BB",struct.pack("H",1)) == (1,0): # little endian
            s = ((s>>8)&0xff)|s<<8
        return s & 0xffff

class IPchecksum(HexShort):
    def work(self):
        if self.isdef():
            return self._content
        copy = IPnochksum()
        copy['header']._subcells = self._parent._subcells
        return checksum(copy.pack())

class IPaddr(Int):
    def repr2work(cls, val):
        if isinstance(val, str):
            val = sum([int(v)<<(8*(3-i)) for i,v in enumerate(val.split('.'))])
        return val
    repr2work = classmethod(repr2work)
    def work2repr(self, val):
        if val is not None:
            val = '%d.%d.%d.%d'%struct.unpack('BBBB',struct.pack('>I',val))
        return val

class IPaddrSrc(IPaddr):
    def work(self):
        if self.isdef():
            return self._content
        return self._parent['dst'].work()

class IPlen(Short):
    def work(self):
        if self.isdef():
            return self._content
        copy = self._parent.__class__()
        copy._subcells = self._parent._subcells
        return copy.packlen() + self._parent._parent['payload'].packlen()

class IPihl(Bits[4]):
    """ Length of the IP header, in 4-bytes words. """
    def _default(self):
        # 'p' is a copy of the IP header, copy needed to have p._pos
        # different from self._parent._pos
        p = self._parent.__class__()
        p._subcells = self._parent._subcells
        return p.packlen() // 4
    _default = property(_default)
    def __getitem__(self, item):
        """ Add virtual attribute 'optionslen' """
        if item == 'optionslen':
            if self._content is None: val = 0
            else:                     val = self._content*4-20
            return Int().unwork(val)
        else:
            log.error("Cannot get %s[%r]", self.__class__.__name__, item)

class IPOption(Scapy,Union):
    _endianess = '>'
    _options = []
ip_options_classes = {'control':0, 'debug':2}
ip_options_names = {}
def add_ip_option(cls):
    cls._endianess = '>'
    IPOption._options.append(cls)
    ip_options_names[cls._optname] = cls().option

class IPOption_EOL(Scapy,Struct):
    _optname = 'end_of_list'
    _fields = [
        ('copy_flag', Bits[1]                     .default(0)),
        ('optclass',  Bits[2][ip_options_classes] .default(0)),
        ('option',    Bits[5][ip_options_names]   .fixed(0)),
        ]
add_ip_option(IPOption_EOL)

class IPOption_NOP(Scapy,Struct):
    _optname = 'nop'
    _fields = [
        ('copy_flag', Bits[1]                     .default(0)),
        ('optclass',  Bits[2][ip_options_classes] .default(0)),
        ('option',    Bits[5][ip_options_names]   .fixed(1)),
        ]
add_ip_option(IPOption_NOP)

"""
class IPOption_Security(Scapy,Struct):
    _optname = 'security'
    _fields = [
        ('copy_flag', Bits[1]                     .default(1)),
        ('optclass',  Bits[2][ip_options_classes] .default(0)),
        ('option',    Bits[5][ip_options_names]   .fixed(2)),
        ('length',    Byte                        .default(11)),
        # below: same as scapy; not compliant with RFC 1108
        ('security',                  Short       .default(0)),
        ('compartment',               Short       .default(0)),
        ('handling_restrictions',     Short       .default(0)),
        ('transmission_control_code', Str[3]      .default('xxx')),
        ]
add_ip_option(IPOption_Security)

class IPOption_LSRR(Scapy,Struct):
    _optname = 'loose_source_route'
    _fields = [
        ('copy_flag', Bits[1]                     .default(1)),
        ('optclass',  Bits[2][ip_options_classes] .default(0)),
        ('option',    Bits[5][ip_options_names]   .fixed(3)),
        ('length',    Byte                        .default(3)),
        ('pointer',   Byte                        .default(4)),
        #('routers',   VarArray[IPaddr]),
        ]
    _rules = [
        #RuleLinear((3,None), (1,'routers.count'), (-1,'length')),
        # meaning that 3 + routers.count - length = 0
        ]
add_ip_option(IPOption_LSRR)

class IPOption_FALLBACK(Scapy,Struct):
    _optname = 'FALLBACK'
    _fields = [
        ('copy_flag', Bits[1]),
        ('optclass',  Bits[2][ip_options_classes]),
        ('option',    Bits[5][ip_options_names]),
        ('length',    Byte                        .default(2)),
        #('data',      VarArray[Byte]),
        ]
    _rules = [
        #RuleLinear((2,None), (1,'data.count'), (-1,'length')),
        ]
add_ip_option(IPOption_FALLBACK)
"""

class IPOptions(Scapy,VarArray):
    _type = IPOption
    # TODO: pad with IPOption_EOL, the bytelength needs to be a multiple of 4

class IP(Layer):
    _endianess = '>'
    _header = [
        ('version', Bits[4]           .default(4)),
        ('ihl',     IPihl),
        ('tos',     Byte              .default(0)),
        ('len',     IPlen),
        ('id',      Short             .default(1)),
        ('flags',   Bits[3]           .default(0)),
        ('frag',    Bits[13]          .default(0)),
        ('ttl',     Byte              .default(64)),
        ('proto',   Byte[PROTO_NAMES] .default('ip')),
        ('chksum',  IPchecksum),
        ('src',     IPaddrSrc),
        ('dst',     IPaddr            .default('127.0.0.1')),
        ('options', IPOptions),
        ]
    _rules = [
        RuleEqual('header.ihl.optionslen', 'header.options.packlen'),
        #RuleLinear((20,None), (1,'header.options.packlen'), (-4,'header.ihl')),

        #RuleLinear((1,'header.packlen'), (1,'payload.packlen'), (-1,'len')),
        # meaning that 'len' is header length plus payload length
        ]
class IPnochksum(IP):
    """ Needed to compute the checksum """
    _header = [_ for _ in IP._header if _[0] != 'chksum']

class TCPchecksum(HexShort):
    def work(self):
        if self.isdef():
            return self._content
        tcp = self._parent._parent
        if tcp._parent is None: return 0 # no underlayer
        ip = tcp._parent._parent
        # pseudo header
        phlen = ip['header'].packlen() + tcp['payload'].packlen()
        p = Struct[[('src',Int),
                    ('dst',Int),
                    ('pad',Byte.default(0)),
                    ('proto',Byte),
                    ('phlen',Short.default(phlen))]]()
        p._endianess = '>'
        p._subcells.update(ip['header']._subcells)
        copy = TCPnochksum()
        copy['header']._subcells = self._parent._subcells
        return checksum(p.pack()+copy.pack()+tcp['payload'].pack())

class TCP(Layer):
    _endianess = '>'
    _header = [
        ('sport',    Short       .default(20)),
        ('dport',    Short       .default(80)),
        ('seq',      Int         .default(0)),
        ('ack',      Int         .default(0)),
        ('dataofs',  Bits[4]     .default(5)),
        ('reserved', Bits[3]     .default(0)),
        ('flags',    Bits[9]     .default(2)),
        ('window',   Short       .default(8192)),
        ('chksum',   TCPchecksum),
        ('urgptr',   Short       .default(0)),
        #('options', TCPOptions),
        ]
class TCPnochksum(TCP):
    """ Needed to compute the checksum """
    _header = [_ for _ in TCP._header if _[0] != 'chksum']

class UDP(Layer):
    _endianess = '>'
    _header = [
        ('sport',    Short       .default(53)),
        ('dport',    Short       .default(53)),
        ('len',      Short),
        ('chksum',   Short),
        ]

bind_layers( IP,            TCP,           frag=0, proto=6)
bind_layers( IP,            UDP,           frag=0, proto=17)

if __name__ == "__main__":
    import sys, os, code
    sys.path.insert(1, os.path.abspath(sys.path[0]+'/../..'))
    import tests
    from tests.test_all import mkbytes
    """
    print([(_, p[_]._value) for _ in p._value])
    v = p._get_value()
    for k in v:
        print(" %10r %r"%(k,v[k].__class__))
        print(" %10r repr %r"%(k,v[k]))
        print(" %10r pack %r"%(k,v[k].pack()))
        print(" %10r work %r"%(k,v[k].work()))
    for k, _ in p._fields:
        print(" %10r work %r"%(k,v[k].work()))
    print(repr(p))
    print(p.show())
    print(p.data())
    print(p.binrepr())
    print("%r=%r"%(p,p.pack()))
    """
    #sys.exit(0)
    code.interact('Interactive Python Console', None, locals())

