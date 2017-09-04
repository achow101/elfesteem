#! /usr/bin/env python

import sys, os
sys.path.insert(1, os.path.abspath(sys.path[0]+'/tests'))
from test_all import run_tests, hashlib, mkbytes
from elfesteem.core.cell import *
from elfesteem.network.inet import *

try:
    # This way, we can use our code with pytest, but we can also
    # use it directly, e.g. when testing for python2.3.
    # No decorator, the syntax is forbidden in python2.3.
    import pytest
    def assertion():
        def inner_assertion(target, value, message):
            assert target == value
        return inner_assertion
    assertion = pytest.fixture(assertion)
except:
    pass

def test_ip(assertion):
    """ Same syntax as scapy for IP() """
    p = IP()
    assertion("<IP  |>", repr(p), "repr(IP())")
    data = mkbytes('E\0\0\x14\0\x01\0\0@\0|\xe7\x7f\0\0\x01\x7f\0\0\x01')
    assertion(data, p.pack(), "IP() bytestring")
    p = IP(data)
    assertion(data, p.pack(), "IP(IP) bytestring")
    text = "<IP  version=4L ihl=5L tos=0x0 len=20 id=1 flags= frag=0L ttl=64 proto=ip chksum=0x7ce7 src=127.0.0.1 dst=127.0.0.1 |>" # original scapy output
    text = "<IP  version=4 ihl=5 tos=0 len=20 id=1 flags=0 frag=0 ttl=64 proto=ip chksum=0x7ce7 src=127.0.0.1 dst=127.0.0.1 |>"     # our output: only cosmetic changes
    assertion(text, repr(p), "repr(IP(IP))")
    p = IP(ihl=5)
    assertion("<IP  ihl=5 |>", repr(p), "repr(IP(ihl=5))")
    assertion(data, p.pack(), "IP(ihl=5).pack()")
    assertion(4, IP().header.version, 'IP version has default value')
    assertion(None, IP().header.len, 'IP len is dynamically computed')
    assertion(4, IP().version, 'IP version direct access')
    assertion(None, IP().len, 'IP len direct access')
    assertion(IP().show(), IP(options=[]).show(), 'IP empty options, show')

def test_ip_options(assertion):
    """ IP header with options """
    data = mkbytes('F\0\0\x18\0\x01\0\0@\0z\xe3\x7f\0\0\x01\x7f\0\0\x01\x01\0\0\0')
    p = IP(data)
    text = "<IP  version=4 ihl=6 tos=0 len=24 id=1 flags=0 frag=0 ttl=64 proto=ip chksum=0x7ae3 src=127.0.0.1 dst=127.0.0.1 options=[<IPOption_NOP  copy_flag=0 optclass=control option=nop |>, <IPOption_EOL  copy_flag=0 optclass=control option=end_of_list |>, <IPOption_EOL  copy_flag=0 optclass=control option=end_of_list |>, <IPOption_EOL  copy_flag=0 optclass=control option=end_of_list |>] |>"
    assertion(text, repr(p), "repr(IP with options)")
    assertion(data, p.pack(), "IP with options, unpack")
    text = "[<IPOption_NOP  copy_flag=0 optclass=control option=nop |>, <IPOption_EOL  copy_flag=0 optclass=control option=end_of_list |>, <IPOption_EOL  copy_flag=0 optclass=control option=end_of_list |>, <IPOption_EOL  copy_flag=0 optclass=control option=end_of_list |>]"
    assertion(text, repr(p.options), "repr(IP.options)")
    text = "<IPOption_NOP  copy_flag=0 optclass=control option=nop |>"
    assertion(text, repr(p.options[0]), "repr(IP.options[0])")
    """ Options alone """
    p = IPOption(mkbytes('\0'))
    assertion(mkbytes('\0'),   p.pack(), "IPOption EOL pack")
    assertion({'copy_flag': 0, 'optclass': 'control', 'option': 'end_of_list'},
              p.repr(), "IPOption EOL repr")
    p = IPOption_NOP()
    assertion(mkbytes('\x01'), p.pack(), "IPOption_NOP pack")
    assertion({'copy_flag': 0, 'optclass': 'control', 'option': 'nop'},
              p.repr(), "IPOption_NOP repr")
    """ Explicit definition of options """
    p = IP(options=[IPOption_NOP(),IPOption_EOL(),IPOption_EOL(),IPOption_EOL()])
    assertion(data, p.pack(), "IP with options, unwork")
    #print(p.show())
    #print(repr(p.pack()))
    #print(repr(IP(p.pack())))
    """ Padding options array to 4 bytes """
    # p = IP(options=[IPOption_NOP()])
    # TODO

def test_ip_invalid(assertion):
    """ Some invalid IP packets """
    p = IP(ihl=6)
    assertion("<IP  ihl=6 |>", repr(p), "repr(IP(ihl=6))")
    x='F\0\0\x14\0\x01\0\0@\0{\xe7\x7f\0\0\x01\x7f\0\0\x01'
    assertion(mkbytes(x), p.pack(), "IP(ihl=6).pack()")

def test_tcp(assertion):
    """ TCP only """
    p = TCP()
    assertion("<TCP  |>", repr(p), "repr(TCP())")
    data = mkbytes('\0\x14\0P\0\0\0\0\0\0\0\0P\x02 \0\0\0\0\0')
    assertion(data, p.pack(), "TCP() bytestring")
    p = TCP(data)
    assertion(data, p.pack(), "TCP(TCP) bytestring")
    text = "<TCP  sport=ftp_data dport=http seq=0 ack=0 dataofs=5L reserved=0L flags=S window=8192 chksum=0x0 urgptr=0 |>" # original scapy output
    text = "<TCP  sport=20 dport=80 seq=0 ack=0 dataofs=5 reserved=0 flags=2 window=8192 chksum=0x0 urgptr=0 |>" # our output, cosmetic changes
    assertion(text, repr(p), "repr(TCP(TCP))")

def test_ip_payload(assertion):
    """ IP with raw payload """
    p = IP()/struct.pack('B',0)
    text = "<IP  |<Raw  load='\\x00' |>>"
    assertion(text, repr(p), "repr(IP/\\0)")
    return
    #p = IP(len=100,chksum=0x6666)/TCP()
    p = IP(str(IP(len=20))+'\0') # should be padding
    print(repr(p))
    p = IP(str(IP(len=100))+'\0')
    print(repr(p))

def test_ip_tcp(assertion):
    """ IP with TCP payload """
    p = IP()/TCP()
    assertion("<IP  frag=0 proto=tcp |<TCP  |>>", repr(p), "repr(IP()/TCP())")
    data = mkbytes('E\0\0(\0\x01\0\0@\x06|\xcd\x7f\0\0\x01\x7f\0\0\x01\0\x14\0P\0\0\0\0\0\0\0\0P\x02 \0\x91|\0\0')
    assertion(data, p.pack(), "IP()/TCP() bytestring")
    p = IP(data)
    assertion(data, p.pack(), "IP(IP/TCP) bytestring")
    text = "<IP  version=4L ihl=5L tos=0x0 len=40 id=1 flags= frag=0L ttl=64 proto=tcp chksum=0x7ccd src=127.0.0.1 dst=127.0.0.1 options=[] |<TCP  sport=ftp_data dport=http seq=0 ack=0 dataofs=5L reserved=0L flags=S window=8192 chksum=0x917c urgptr=0 |>>" # original scapy output
    text = "<IP  version=4 ihl=5 tos=0 len=40 id=1 flags=0 frag=0 ttl=64 proto=tcp chksum=0x7ccd src=127.0.0.1 dst=127.0.0.1 |<TCP  sport=20 dport=80 seq=0 ack=0 dataofs=5 reserved=0 flags=2 window=8192 chksum=0x917c urgptr=0 |>>" # our output, cosmetic changes
    assertion(text, repr(p), "repr(IP(IP/TCP))")
    p = IP(proto=6)/TCP().pack()
    p = IP(p.pack())
    text = "<IP  version=4 ihl=5 tos=0 len=40 id=1 flags=0 frag=0 ttl=64 proto=tcp chksum=0x7ccd src=127.0.0.1 dst=127.0.0.1 |<TCP  sport=20 dport=80 seq=0 ack=0 dataofs=5 reserved=0 flags=2 window=8192 chksum=0x0 urgptr=0 |>>" # our output, no TCP checksum
    assertion(text, repr(p), "repr(IP(IP.proto=tcp/[TCP]))")
    text = "<IP  version=4L ihl=5L tos=0x0 len=40 id=1 flags= frag=0L ttl=64 proto=ip chksum=0x7cd3 src=127.0.0.1 dst=127.0.0.1 options=[] |<Raw  load='\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\x00\x00\x00\x00' |>>" # original scapy output
    text = "<IP  version=4 ihl=5 tos=0 len=40 id=1 flags=0 frag=0 ttl=64 proto=ip chksum=0x7cd3 src=127.0.0.1 dst=127.0.0.1 |<Raw  load='\\x00\\x14\\x00P\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00P\\x02 \\x00\\x00\\x00\\x00\\x00' |>>" # our output, cosmetic changes
    p = IP()/TCP().pack()
    p = IP(p.pack())
    assertion(text, repr(p), "repr(IP(IP/[TCP]))")

def test_ip_tcp_data(assertion):
    """ IP with TCP payload, with raw payload """
    text = "<IP  frag=0 proto=tcp |<TCP  |<Raw  load='\\x00' |>>>"
    p = IP()/(TCP()/mkbytes('\0'))
    assertion(text, repr(p), "repr(IP/(TCP/\\0))")
    p = IP()/TCP()/mkbytes('\0')
    assertion(text, repr(p), "repr(IP/TCP/\\0)")
    for chksum, raw in (
           (0x917c, ''),
           (0x917b, '\0'),
           (0x907b, '\x01'),
           (0x6001, '\0x1'),
           ):
       p = IP()/TCP()/mkbytes(raw)
       assertion(chksum, p['payload']['header']['chksum'].work(),
           "TCP checksum %#x"%chksum)

def test_sublayer_access(assertion):
    """ IP with TCP payload, sublayer access """
    p = IP()/TCP()
    assertion("<TCP  |>", repr(p[TCP]), "repr(p[TCP])")
    text = "<IP  frag=0 proto=tcp |<TCP  |<Raw  load='\\x00' |>>>"
    p = IP()/TCP()/mkbytes('\0')
    assertion(p,                     p[IP],  "p[IP]")
    assertion(p['payload']._wrapped, p[TCP], "p[TCP]")
    tst = 'Non existent sublayer'
    msg = "'Layer [UDP] not found'"
    try:
        p[UDP]
        assertion(0,1, "%s should have raised a KeyError"%tst)
    except KeyError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)


def run_test(assertion):
    for name, value in dict(globals()).items():
        if name.startswith('test_'):
            value(assertion)

if __name__ == "__main__":
    run_tests(run_test)
