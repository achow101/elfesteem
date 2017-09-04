#! /usr/bin/env python

from test_all import run_tests, hashlib, mkbytes
from elfesteem.core.binrepr import *
import sys

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

def test_binary_representation(assertion):
    """ Binary representation that can deal with sparse or overlapping data. """
    r = BinRepr()
    assertion(mkbytes(''), r.pack(),
        'Empty BinRepr')
    r = BinRepr(mkbytes('one'))
    assertion(mkbytes('one'), r.pack(),
        'BinRepr with some data')
    r += mkbytes('two')
    assertion(mkbytes('onetwo'), r.pack(),
        'Append bytestring to BinRepr')
    assertion(mkbytes('w'), r[4],
        'One non-overlapped byte')
    assertion(mkbytes('etw'), r[2:5],
        'Three bytes across two chunks')
    ubyte_msg = "ubyte format requires 0 <= number <= 255"
    if sys.version_info[:2] == (2, 3):
        ubyte_msg = "ubyte format requires 0<=number<=255"
    try:
        r[4:7]
        assertion(0,1, "Should fail, invalid padding in chunk")
    except struct.error:
        e = sys.exc_info()[1]
        assertion(ubyte_msg, str(e), 'Invalid padding')
    assertion(mkbytes('wo\0'), r.get_slice(4, 7, paddingbyte=0),
        'Segment with final padding')
    assertion(mkbytes('\0\0on'), r.get_slice(-2, 2, paddingbyte=0),
        'Segment with initial padding')
    r += BinRepr(mkbytes('three'))
    assertion(mkbytes('onetwothree'), r.pack(),
        'Append BinRepr to BinRepr')
    assertion(None, r.data.find(4),
        'No chunk at 4')
    assertion(None, r.split_at(-2),
        'Split before all chunks')
    assertion([mkbytes('two')], r.split_at(3).data,
        'Split at existing chunk')
    assertion([mkbytes('wo')], r.split_at(4).data,
        'Split in existing chunk')
    assertion(None, r.split_at(20),
        'Split after all chunks')
    assertion(mkbytes('onetwothree'), r.pack(),
        'Split does not change pack()')
    chunk = r.data.find(4)
    assertion([mkbytes('wo')], chunk.data,
        'A chunk at 4')
    r = BinRepr()
    r[10] = mkbytes('one')
    assertion(struct.pack("B",0)*10+mkbytes('one'),
        r.pack(paddingbyte=0),
        'BinRepr with padding 0')
    try:
        r.pack()
        assertion(0,1, "Should fail, invalid padding")
    except struct.error:
        e = sys.exc_info()[1]
        assertion(ubyte_msg, str(e), 'Invalid padding')
    r[9] = mkbytes('and')
    try:
        r.pack()
        assertion(0,1, "Should fail, overlapping chunks (1)")
    except ValueError:
        e = sys.exc_info()[1]
        assertion("Overlapping chunks at 10", str(e), 'Overlapping chunks (1)')
    assertion([mkbytes('on'),mkbytes('nd')],
        r.data.x[1].data,
        'BinRepr overlap: two chunks')
    assertion([mkbytes('o'),mkbytes('n')], r[10],
        'One overlapped byte')
    try:
        print(r[10:12])
        assertion(0,1, "Should fail, overlapping chunks (2)")
    except ValueError:
        e = sys.exc_info()[1]
        assertion("Overlapping chunks", str(e), 'Overlapping chunks (2)')
    assertion(mkbytes('nde'),
        r.get_slice(10, 13, paddingbyte=0, overwrite=True),
        'Segment with overlap')
    assertion(struct.pack("B",0)*9+mkbytes('ande'),
        r.pack(paddingbyte=0,overwrite=True),
        'BinRepr with padding 0 and overlap')
    r = BinRepr()
    r[0] = mkbytes('one')
    assertion(mkbytes('one'), r.pack(),
        'BinRepr assignment at offset 0')
    r[1] = mkbytes('ne')
    assertion(mkbytes('one'), r.pack(),
        'BinRepr identical assignment at offset 1')
    r[1] = mkbytes('one')
    try:
        r.pack()
        assertion(0,1, "Should fail, overlapping chunks (3)")
    except ValueError:
        e = sys.exc_info()[1]
        assertion("Overlapping chunks at 1", str(e), 'Overlapping chunks (3)')
    assertion(mkbytes('oone'), r.pack(overwrite=True),
        'BinRepr assignment at offset 1')
    r[2] = BinRepr(mkbytes('two'))
    assertion(mkbytes('ootwo'), r.pack(overwrite=True),
        'BinRepr assignment at offset 2')
    r[1] = mkbytes('zz')
    assertion(mkbytes('ozzwo'), r.pack(overwrite=True),
        'BinRepr new assignment at offset 1')
    r[1:6] = mkbytes('vvvvv')
    assertion(mkbytes('ovvvvv'), r.pack(),
        'BinRepr overwriting assignment (1)')
    r = BinRepr()
    r[1] = mkbytes('ab')
    r[0:2] = mkbytes('vv')
    assertion(mkbytes('vvb'), r.pack(),
        'BinRepr overwriting assignment (2)')
    r = BinRepr()
    r[1] = mkbytes('ab')
    r[8] = mkbytes('vv')
    assertion(mkbytes('\0ab\0\0\0\0\0vv\0\0\0\0\0'),
        r.get_slice(0, 15, paddingbyte=0),
        'Segment with holes')
    r[9] = mkbytes('x')
    assertion(mkbytes('\0ab\0\0\0\0\0vx\0\0\0\0\0'),
        r.get_slice(0, 15, paddingbyte=0, overwrite=True),
        'Segment with holes')
    r = BinRepr()
    assertion(mkbytes('@'*10),
        r.get_slice(0, 10, paddingbyte=0x40),
        'Empty segment')

def test_binary_operations(assertion):
    """ There can be bitwise operations. """
    r = BinRepr(mkbytes('\x02\x03'))
    s = BinRepr(mkbytes('\x42'))
    r.xor(s, offset=1)
    assertion(mkbytes('\x02\x41'), r.pack(),
        'BinRepr xor without extension')
    r = BinRepr(mkbytes('\x02\x03'))
    s = BinRepr(mkbytes('\x42\xcc'))
    r.xor(s, offset=1)
    assertion(mkbytes('\x02\x41\xcc'), r.pack(),
        'BinRepr xor with extension')


def run_test(assertion):
    for name, value in dict(globals()).items():
        if name.startswith('test_'):
            value(assertion)

if __name__ == "__main__":
    run_tests(run_test)
