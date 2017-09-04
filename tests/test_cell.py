#! /usr/bin/env python

import sys, os
sys.path.insert(1, os.path.abspath(sys.path[0]+'/tests'))
from test_all import run_tests, hashlib, mkbytes
from elfesteem.core.cell import *

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

def test_simple_leaf(assertion):
    """ Simple types, with no subcell: generic tests. """
    data = struct.pack('<III',10,20,30)
    if sys.version_info[0] == 3: longval = 10+(20<<32)
    else:                        longval = eval("10L+(20L<<32)")
    for TYPE, LEN, WORK, PACK, PARSED in (
        (Data,              len(data), None,   None,                data),
        (Int,               4,         None,   None,                10),
        (Int.default(0),    4,         0,      struct.pack('<I',0), 10),
        (Int.default(2),    4,         2,      struct.pack('<I',2), 10),
        (Byte.default(0),   1,         0,      struct.pack('B',0),  10),
        (Short.default(0),  2,         0,      struct.pack('<H',0), 10),
        (Quad.default(0),   8,         0,      struct.pack('<Q',0), longval),
        ):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion(None,          cell._content,  '%s._content no data'%NAME)
        assertion(WORK,          cell.work(),    '%s.work() no data'%NAME)
        assertion(PACK,          cell.pack(),    '%s.pack() no data'%NAME)
        if PACK is not None:
            assertion(LEN,       cell.packlen(), '%s.packlen() no data'%NAME)
        assertion((cell,[]),     cell.path(),    '%s.path()'%NAME)
        cell = TYPE().unpack(data)
        assertion(PARSED,        cell.work(),    '%s.unpack().work()'%NAME)
        assertion(data[:LEN],    cell.pack(),    '%s.unpack().pack()'%NAME)
        cell = TYPE().unwork(PARSED)
        assertion(data[:LEN],    cell.pack(),    '%s.unwork().pack()'%NAME)
        assertion(PARSED,        cell.work(),    '%s.unwork().work()'%NAME)
        cell = TYPE().unpack(data, offset=4)
        assertion(data[4:LEN+4], cell.pack(),    '%s.unpack(offset)'%NAME)
        cell = TYPE(data)
        if LEN == len(data): not_parsed = []
        else:                not_parsed = [slice(LEN, len(data))]
        assertion(not_parsed,
            cell.not_parsed.ranges,
            "%s(data) not everything parsed"%NAME)
        assertion(data[:LEN],    cell.pack(),    '%s(data).pack()'%NAME)
        assertion(data,
            cell.pack(with_holes=True),
            '%s(data).pack(with_holes=True)'%NAME)
        cell.unwork(None)
        assertion(WORK,          cell.work(),    '%s.unwork(None)'%NAME)
    try:
        cell = Int().unwork('')
        assertion(0,1, "Should fail, not an integer")
    except TypeError:
        pass

def test_data(assertion):
    """ 'Data' type has many specific methods """
    data = mkbytes("abcdefgh")
    cell = Data(data)
    assertion(8,    cell.packlen(), "Data.packlen")
    assertion(data, cell.pack(),    "Data.pack")
    assertion(data, cell.work(),    "Data.work")
    cell = Data().unpack(data, offset=2)
    assertion(6,        cell.packlen(), "Data offset=2 packlen")
    assertion(data[2:], cell.pack(),    "Data offset=2 pack")
    assertion(data[2:], cell.work(),    "Data offset=2 work")
    cell = Data().unpack(data, offset=2, size=2)
    assertion(2,         cell.packlen(), "Data offset=2 size=2 packlen")
    assertion(data[2:4], cell.pack(),    "Data offset=2 size=2 pack")
    assertion(data[2:4], cell.work(),    "Data offset=2 size=2 work")
    cell = Data(data)
    assertion(mkbytes("cd"), cell[2:4], "Data[2:4]")
    cell[2:4] = mkbytes("XX")
    assertion(mkbytes("abXXefgh"), cell.pack(), "Data[2:4]='XX'")
    cell[3] = mkbytes("Y")
    assertion(mkbytes("abXYefgh"), cell.pack(), "Data[3]='Y'")
    try:
        cell[2:4] = mkbytes("XXX")
        assertion(0,1, "Should fail, not same size")
    except AssertionError:
        pass
    cell = Data(data)
    assertion(8,    cell['packlen'].work(), "Data packlen 8")
    cell = Data()
    assertion(None, cell['packlen'].work(), "Data packlen None")
    cell['packlen'].unwork(4)
    assertion(4,    cell['packlen'].work(), "Data packlen 4")
    cell.unpack(data)
    assertion(data[:4], cell.pack(), "Data unpack packlen=4")

def test_enum(assertion):
    """ Simple numeric types, with named values. """
    DICT = {'ZERO':0, 'ONE':1, 'TWO':2}
    class Enum0(Int):
        _enum = DICT
        _content = 0
    cell = Enum0()
    assertion(0,                              cell.work(), 'Enum0 0 work')
    assertion('ZERO',                         cell.repr(), 'Enum0 0 repr')
    assertion("<Enum0 value=ZERO>",           cell.show(), 'Enum0 0 show')
    cell.unwork(1)
    assertion(1,                              cell.work(), 'Enum0 1 work')
    assertion('ONE',                          cell.repr(), 'Enum0 1 repr')
    assertion("<Enum0 value=ONE>",            cell.show(), 'Enum0 1 show')
    Enum1 = Int.default(1)
    Enum1._enum = DICT
    cell = Enum1()
    assertion(1,                              cell.work(), 'Enum1 1 work')
    assertion('ONE',                          cell.repr(), 'Enum1 1 repr')
    assertion("<Int.default(1) value=ONE>",   cell.show(), 'Enum1 1 show')
    Enum2 = Int[DICT].default(2)
    cell = Enum2()
    assertion(2,                                  cell.work(), 'Enum2 2 work')
    assertion('TWO',                              cell.repr(), 'Enum2 2 repr')
    assertion("<Int[enum].default(2) value=TWO>", cell.show(), 'Enum2 2 show')
    Enum2 = Int[DICT].default('TWO')
    cell = Enum2()
    assertion(2,                              cell.work(), 'Enum2 TWO work')
    assertion('TWO',                          cell.repr(), 'Enum2 TWO repr')
    assertion("<Int[enum].default('TWO') value=TWO>", cell.show(), 'Enum2 TWO show')
    NAMED = NamedConstants((
        (0, 'ZERO'),
        (1, 'ONE'),
        (2, 'TWO'),
        ))
    Enum3 = Int[NAMED].default(1)
    cell = Enum3()
    assertion(1,                                  cell.work(), 'Enum3 1 work')
    assertion('ONE',                              cell.repr(), 'Enum1 1 repr')
    assertion("<Int[enum].default(1) value=ONE>", cell.show(), 'Enum3 1 show')
    class Enum4(Bits[4]):
        _enum = {'zero':0, 'one':1}
    cell = Enum4()
    cell.unwork(0)
    assertion("<Enum4 value=zero>",               cell.show(), 'Enum4 0 show')
    Enum5 = Bits[4][{'zero':0, 'one':1}]
    cell = Enum5()
    cell.unwork(0)
    assertion("<Numeric[enum] value=zero>",       cell.show(), 'Enum5 0 show')
    cell.unwork(7)
    assertion("<Numeric[enum] value=7>",          cell.show(), 'Enum5 7 show')
    Enum6 = Bits[4][{'zero':0, 'one':1}].default(1)
    cell = Enum6()
    assertion("<Numeric[enum].default(1) value=one>", cell.show(), 'Enum6 show')
    Enum7 = Bits[4][{'zero':0, 'one':1}].fixed(1)
    cell = Enum7()
    assertion("<Numeric[enum].fixed(1) value=one>", cell.show(), 'Enum7 show')

def test_int_endianess(assertion):
    class LittleEndianInt(Int):
        _endianess = '<'
    class BigEndianInt(Int):
        _endianess = '>'
    for TYPE in (LittleEndianInt, BigEndianInt):
        NAME = TYPE.__name__
        data = struct.pack(TYPE._endianess+'I',1)
        cell = TYPE().unwork(1)
        assertion(data, cell.pack(), "%s unwork+pack"%NAME)
        cell = TYPE(data)
        assertion(1,    cell.work(), "%s unpack+work"%NAME)

def test_ptr_endianess_ptrsize(assertion):
    class LittleEndian32(Ptr):
        _endianess = '<'
        _ptrsize   = 32
    class BigEndian32(Ptr):
        _endianess = '>'
        _ptrsize   = 32
    class LittleEndian64(Ptr):
        _endianess = '<'
        _ptrsize   = 64
    class BigEndian64(Ptr):
        _endianess = '>'
        _ptrsize   = 64
    for TYPE in (LittleEndian32, BigEndian32, LittleEndian64, BigEndian64):
        NAME = TYPE.__name__
        fmt = {32: 'I', 64: 'Q'}[TYPE._ptrsize]
        data = struct.pack(TYPE._endianess+fmt,1)
        cell = TYPE().unwork(1)
        assertion(data, cell.pack(), "%s unwork+pack"%NAME)
        cell = TYPE(data)
        assertion(1,    cell.work(), "%s unpack+work"%NAME)
        assertion("<%s value=%s>"%(NAME,
                {32: '0x00000001', 64: '0x0000000000000001'}[TYPE._ptrsize]),
            cell.show(), "%s unpack+show"%NAME)

def test_endianess_ptrsize_struct(assertion):
    class FLE(Struct):
        _ptrsize = 32
        _endianess = '<'
        _fields = [
            ('one',      Int),
            ('two',      Ptr),
            ('three',    Short),
            ]
    data = struct.pack("<IQH",10,12,14)
    cell = FLE(data)
    assertion(10, cell.packlen(), 'FLE.packlen')
    assertion([slice(10,14)],
        cell.not_parsed.ranges,
        "FLE(data) not everything parsed")
    assertion(data,
        cell.pack(with_holes=True),
        'FLS1(data).pack(with_holes=True)')
    assertion(10, cell['one'].work(), 'Int 32-bit little endian')
    assertion(12, cell['two'].work(), 'Ptr 32-bit little endian')
    assertion(0, cell['three'].work(), 'Short 32-bit little endian')
    FLE._ptrsize = 64
    cell = FLE(data)
    assertion(10, cell['one'].work(), 'Int 64-bit little endian')
    assertion(12, cell['two'].work(), 'Ptr 64-bit little endian')
    assertion(14, cell['three'].work(), 'Short 64-bit little endian')
    FLE._endianess = '>'
    cell = FLE(data)
    assertion(0x0a000000, cell['one'].work(), 'Int 64-bit big endian')
    assertion(0x0c00000000000000, cell['two'].work(), 'Ptr 64-bit big endian')
    assertion(0x0e00, cell['three'].work(), 'Short 64-bit big endian')

def test_node(assertion):
    """ Simple node, a struct in reality """
    class SimpleNode(Node):
        _layout = [
            ('a', (Int.default(1), lambda s,k:0)),
            ('b', (Int.default(2), lambda s,k:4)),
            ('c', (Int.default(3), lambda s,k:8)),
            ]
    class NoneNode(Node):
        _layout = [
            ('a', (Int, lambda s,k:0)),
            ('b', (Int, lambda s,k:4)),
            ('c', (Int, lambda s,k:8)),
            ]
    DefaultNode = NoneNode.default({'a': 1, 'b': 2, 'c': 3})
    for TYPE in (SimpleNode, DefaultNode):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion(12,                     cell.packlen(), '%s.packlen'%NAME)
        assertion({'a': 1,'b': 2,'c': 3}, cell.work(), "%s.work"%NAME)
        assertion({'a': 1,'b': 2,'c': 3}, cell.repr(), "%s.repr"%NAME)
        data = struct.pack("<III",1,2,3)
        assertion(data,                   cell.pack(), "%s.pack"%NAME)
        assertion((cell,[]),              cell.path(), '%s.path()'%NAME)
        assertion((cell,['a']),           cell['a'].path(), '%s[a].path()'%NAME)
        cell.unpack(struct.pack("<III",10,11,12))
        assertion({'a':10,'b':11,'c':12}, cell.work(), "%s.unpack"%NAME)
        cell = TYPE(struct.pack("<III",20,21,22))
        assertion({'a':20,'b':21,'c':22}, cell.work(), "%s(data)"%NAME)
        cell = TYPE(a=30,b=31,c=32)
        assertion({'a':30,'b':31,'c':32}, cell.work(), "%s(x=v,.)"%NAME)
        cell = TYPE(a=40)
        assertion({'a':40,'b': 2,'c': 3}, cell.work(), "%s(x=v)"%NAME)
        cell.unwork({'b':41})
        assertion({'a': 1,'b':41,'c': 3}, cell.work(), "%s.unwork"%NAME)
        cell.unrepr(c=42)
        assertion({'a': 1,'b': 2,'c':42}, cell.work(), "%s.unrepr"%NAME)
        assertion("\n".join(["<%s"%NAME,
                  "  'a' at 0x0: <Int.default(1) value=1>",
                  "  'b' at 0x4: <Int.default(2) value=2>",
                  "  'c' at 0x8: <Int.default(3) value=42>",
                  ">"]), cell.show(), "%s.show"%NAME)
        assertion("<Int.default(3) value=42>",
                  cell['c'].show(), "%s['c'].show"%NAME)
        cell['a'].unwork(6)
        work = {'a':6,'b': 2,'c':42}
        assertion(work, cell.work(), "%s[].unwork"%NAME)
        cell2 = TYPE()
        assertion(work, cell.work(), "%s side effects"%NAME)
        data = [_._default for _ in cell]
        assertion([1,2,3], data, "%s iteration in deterministic order"%NAME)
        data = [_._name for _ in cell]
        assertion(['a','b','c'], data, "%s iteration, names"%NAME)

def test_node_invalid_definitions(assertion):
    """ Invalid definitions of Node types """
    tst = 'Duplicate invalid definition'
    msg = "Duplicate field 'a'"
    try:
        class Duplicate(Node):
            _layout = [
                ('a', (Int.default(1), lambda s,k:0)),
                ('a', (Int.default(2), lambda s,k:4)),
                ]
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = "MissingPos1 invalid definition"
    try:
        class MissingPos1(Node):
            _layout = [
                ('a', (Int.default(1), lambda s,k:0)),
                ('b', (Int.default(2), lambda s,k:4)),
                ('c', (Int.default(3),)),
                ]
        assertion(0,1, "%s should have raised a ValueError"%tst)
    except ValueError:
        e = sys.exc_info()[1]
        msg = "need more than 1 value to unpack"
        if sys.version_info[0:2] == (2, 3):
            msg = "unpack tuple of wrong size"
        try:
            import __pypy__
            msg = "expected length 2, got 1"
        except ImportError:
            pass
        if sys.version_info[0:2] in [(3, 5), (3, 6)]:
            msg = "not enough values to unpack (expected 2, got 1)"
        assertion(msg, str(e), "%s:%s"%(tst,e))
    tst = "MissingPos2 invalid definition"
    msg = "Field 'c' should be defined with a tuple"
    try:
        class MissingPos2(Node):
            _layout = [
                ('a', (Int.default(1), lambda s,k:0)),
                ('b', (Int.default(2), lambda s,k:4)),
                ('c', Int.default(3)),
                ]
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), "%s:%s"%(tst,e))
    tst = "NotTuples invalid definition"
    try:
        class NotTuples(Node):
            _layout = [ 'a', 'b' ]
        assertion(0,1, "%s should have raised a ValueError"%tst)
    except ValueError:
        e = sys.exc_info()[1]
        msg = "need more than 1 value to unpack"
        if sys.version_info[0:2] in [(3, 5), (3, 6)]:
            msg = "not enough values to unpack (expected 2, got 1)"
        assertion(msg, str(e), "%s:%s"%(tst,e))
    class EmptyLayout(Node):
        _layout = [ ]
    try:
        class InvalidLayout(Node):
            _layout = None
        assertion(0,1, "InvalidLayout should have raised an exception")
    except TypeError:
        pass

def test_node_node(assertion):
    """ Two levels; tricky offset computation """
    class SimpleNode(Node):
        _layout = [
            ('a', (Int.default(1), lambda s,k:0)),
            ('b', (Int.default(2), lambda s,k:4)),
            ]
    class DoubleNode(Node):
        _layout = [
            ('x', (SimpleNode,     lambda s,k:0)),
            ('y', (Int.default(7), lambda s,k:8)),
            ('z', (SimpleNode,     lambda s,k:12)),
            ]
    cell = DoubleNode()
    assertion(20,                       cell.packlen(), "DoubleNode.packlen")
    assertion(struct.pack("<IIIII",1,2,7,1,2),cell.pack(), "DoubleNode.pack")
    textz = "\n".join(["<SimpleNode",
      "    'a' at 0xc: <Int.default(1) value=1>",
      "    'b' at 0x10: <Int.default(2) value=2>",
      "  >"])
    text = "\n".join(["<DoubleNode",
      "  'x' at 0x0: <SimpleNode",
      "    'a' at 0x0: <Int.default(1) value=1>",
      "    'b' at 0x4: <Int.default(2) value=2>",
      "  >",
      "  'y' at 0x8: <Int.default(7) value=7>",
      "  'z' at 0xc: <SimpleNode",
      "    'a' at 0xc: <Int.default(1) value=1>",
      "    'b' at 0x10: <Int.default(2) value=2>",
      "  >",
      ">"])
    assertion(textz, cell['z'].show(), "SimpleNode.show (before)")
    assertion(text,  cell.show(),      "DoubleNode.show")
    assertion(textz, cell['z'].show(), "SimpleNode.show (after)")
    assertion((cell,[]),        cell.path(),           'DoubleNode.path()')
    assertion((cell,['x']),     cell['x'].path(),      'DoubleNode[x].path()')
    assertion((cell,['x','a']), cell['x']['a'].path(), 'DoubleNode[x.a].path()')

def test_struct(assertion):
    """ Struct is a concatenation of cells with various types. """
    class Simple(Struct):
        _fields = [
            ('a', Int.default(1)),
            ('b', Int.default(2)),
            ]
    class Other(Simple):
        """ Just to test heritage """
    class Default(Struct):
        _fields = [
            ('a', Int),
            ('b', Int),
            ]
        _default = {'a': 1, 'b': 2}
    class Basic(Struct):
        _fields = [
            ('a', Int),
            ('b', Int),
            ]
    BDefault = Basic.default({'a': 1, 'b': 2})
    OneLine = Struct[[('a', Int.default(1)), ('b', Int.default(2))]]
    for TYPE in (Simple, Other, Default, BDefault, OneLine):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion(8,                     cell.packlen(), "%s.packlen"%NAME)
        assertion({'a': 1, 'b': 2},      cell.work(), "%s.work"%NAME)
        assertion({'a': 1, 'b': 2},      cell.repr(), "%s.repr"%NAME)
        assertion(struct.pack("<II",1,2),cell.pack(), "%s.pack"%NAME)
        assertion((cell,[]),             cell.path(), '%s.path()'%NAME)
        assertion((cell,['a']),          cell['a'].path(), '%s[a].path()'%NAME)
        cell = TYPE(struct.pack("<II",20,21))
        assertion({'a':20, 'b':21},      cell.work(), "%s(data)"%NAME)
        cell = TYPE(a=30,b=31)
        assertion({'a':30, 'b':31},      cell.work(), "%s(x=v,.)"%NAME)

def test_struct_struct(assertion):
    """ Two levels; tricky offset computation """
    class SimpleStruct(Struct):
        _fields = [
            ('a', Int.default(1)),
            ('b', Int.default(2)),
            ]
    class DoubleStruct(Struct):
        _fields = [
            ('x', SimpleStruct),
            ('y', Int.default(7)),
            ('z', SimpleStruct),
            ]
    cell = DoubleStruct()
    assertion(struct.pack("<IIIII",1,2,7,1,2),cell.pack(), "DoubleStruct.pack")
    assertion(20,              cell.packlen(),       "DoubleStruct.packlen")
    assertion((cell,[]),       cell.path(),          'DoubleStruct.path()')
    assertion((cell,['x']),    cell['x'].path(),     'DoubleStruct[x].path()')
    assertion((cell,['x','a']),cell['x']['a'].path(),'DoubleStruct[x.a].path()')

def test_array(assertion):
    """ Array is a concatenation of cells with identical type. """
    """
    cell = ArraySparse[Int.default(1),3]()
    print(cell.work())
    print(repr(cell.pack()))
    print(cell.repr())
    print(cell.show())
    """
    class SimpleArray(Array):
        _type = Int
        _count = 3
    for TYPE in (SimpleArray, Array[Int,3]):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion(12,                    cell.packlen(), "%s.packlen"%NAME)
        assertion({0:None,1:None,2:None},cell.work(), "%s.work"%NAME)
        assertion([None, None, None],    cell.repr(), "%s.repr"%NAME)
        assertion(None,                  cell.pack(), "%s.pack"%NAME)
        assertion((cell,[]),             cell.path(), '%s.path()'%NAME)
        assertion((cell,[1]),            cell[1].path(), '%s[1].path()'%NAME)
        cell.unrepr([2, 2, 2])
        assertion([2, 2, 2],             cell.repr(), "%s.repr2"%NAME)
        data = struct.pack("<III",2,2,2)
        assertion(data,                  cell.pack(), "%s.pack2"%NAME)
        cell.unwork({1: 4})
        assertion([None, 4, None],       cell.repr(), "%s.repr4"%NAME)
        cell[2].unwork(6)
        assertion([None, 4, 6],          cell.repr(), "%s.repr6"%NAME)
        cell = TYPE()
        cell.unwork({1: 4})
        assertion([None, 4, None],       cell.repr(), "%s.repr"%NAME)
        cell.unpack(data)
        assertion([2, 2, 2],             cell.repr(), "%s.unpack"%NAME)
        cell = TYPE(data)
        assertion([2, 2, 2],             cell.repr(), "%s(data)"%NAME)
        tst = "%s.unrepr([3,3]) too small"%NAME
        msg = "%s length should be 3, cannot be set at 2"%NAME
        try:
            cell.unrepr([3, 3])
            assertion(0,1, "%s should have raised a CellError"%tst)
        except CellError:
            e = sys.exc_info()[1]
            assertion(msg, str(e), tst)
        tst = "%s.unrepr([3,3,3,3]) too big"%NAME
        msg = "%s length should be 3, cannot be set at 4"%NAME
        try:
            cell.unrepr([3, 3, 3, 3])
            assertion(0,1, "%s should have raised a CellError"%tst)
        except CellError:
            e = sys.exc_info()[1]
            assertion(msg, str(e), tst)
    class Int0Array(Array):
        _type = Int.default(0)
        _count = 3
    for TYPE in (Int0Array, Array[Int.default(0),3]):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion(12,   cell.packlen(), "%s.packlen"%NAME)
        data = struct.pack('<III',0,0,0)
        assertion(data, cell.pack(), '%s.pack() no data'%NAME)
        data = struct.pack('<III',1,2,3)
        cell.unpack(data)
        assertion(data, cell.pack(), '%s.pack() simple data'%NAME)
        assertion(2, cell[1].work(), '%s member'%NAME)
        cell[1].unwork(10)
        assertion([1, 10, 3], cell.repr(), '%s member modification'%NAME)
        cell.unrepr([10,11,12])
        assertion([10,11,12], cell.repr(), '%s unrepr'%NAME)
        tst = "%s.unrepr([3,3,3,3]) too big"%NAME
        msg = "%s length should be 3, cannot be set at 4"%NAME
        try:
            cell.unrepr([3,3,3,3])
            assertion(0,1, "%s should have raised a CellError"%tst)
        except CellError:
            e = sys.exc_info()[1]
            assertion(msg, str(e), tst)
    data = [10, 11, 12]
    class DefaultArray(Array):
        _type = Int
        _count = 3
        _default = data
    for TYPE in (DefaultArray, Array[Int,3].default(data)):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion(data, cell.repr(), "%s default"%NAME)
    EmptyArray = Array[Int,0]
    cell = EmptyArray()
    assertion([],              cell.repr(), "EmptyArray.repr")
    assertion(struct.pack(''), cell.pack(), "EmptyArray.pack")

def test_string(assertion):
    TYPE = Str[3]
    NAME = TYPE.__name__
    cell = TYPE(mkbytes('ABC'))
    assertion(3,                      cell.packlen(), "%s.packlen"%NAME)
    assertion({0: 65, 1: 66, 2: 67},  cell.work(), "%s.work"%NAME)
    assertion('ABC',                  cell.repr(), "%s.repr"%NAME)
    assertion(mkbytes('ABC'),         cell.pack(), "%s.pack"%NAME)
    assertion((cell,[]),              cell.path(), '%s.path()'%NAME)
    assertion((cell,[1]),             cell[1].path(), '%s[1].path()'%NAME)
    cell.unrepr('XYZ')
    assertion('XYZ',                  cell.repr(), "%s.repr"%NAME)
    cell = TYPE()
    assertion({0:None,1:None,2:None}, cell.work(), "%s default"%NAME)
    tst = "Invalid string has no repr"
    try:
        cell.repr()
        assertion(0,1, "%s should have raised a TypeError"%tst)
    except TypeError:
        e = sys.exc_info()[1]
        if sys.version_info[0] == 2:
            msg = 'an integer is required'
        elif sys.version_info[0:2] == (3, 2):
            msg = 'an integer is required'
        else:
            msg = 'an integer is required (got type NoneType)'
        try:
            import __pypy__
            msg = "expected integer, got NoneType object"
        except ImportError:
            pass
        assertion(msg, str(e), "%s:%s"%(tst,e))
    TYPE = Str[4].default('TEST')
    cell = TYPE()
    assertion(mkbytes('TEST'), cell.pack(), "%s default"%TYPE.__name__)
    TYPE = Str['TEST']
    cell = TYPE()
    assertion(mkbytes('TEST'), cell.pack(), "%s default"%TYPE.__name__)
    try:
        Str[2]().unrepr(2)
        assertion(0,1, "Should fail, not a string")
    except TypeError:
        pass
    tst = "Str[2]: cannot unwork str"
    msg = "Str[2]: cannot unwork str"
    try:
        Str[2]().unwork('TOTO')
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_string_length(assertion):
    """ Unpack fixed-length string with inappropriate data. """
    tst = 'Unpack fixed-length string with not enough data'
    msg = "Unpack 'Char' with not enough data"
    TYPE = Str[8]
    try:
        cell = TYPE(struct.pack('<I',0))
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = 'Unrepr fixed-length string with not enough data'
    msg = "%s length should be 8, cannot be set at 5"%TYPE.__name__
    try:
        cell = TYPE().unrepr('short')
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = 'Unrepr fixed-length string with too much data'
    msg = "%s length should be 8, cannot be set at 9"%TYPE.__name__
    try:
        cell = TYPE().unrepr('very long')
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_fixed(assertion):
    """ Fixed cells raise an error if with wrong value """
    TYPE = Int.fixed(3)
    cell = TYPE()
    assertion(3, cell.repr(), 'Int fixed')
    cell.unwork(3)
    assertion(3, cell.repr(), 'Int fixed unwork OK')
    cell.unpack(struct.pack('<I',3))
    assertion(3, cell.repr(), 'Int fixed unpack OK')
    tst = "Int fixed unwork"
    msg = "Int.fixed(3) fixed at 3, cannot be set at 7"
    try:
        cell.unwork(7)
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = "Int fixed unpack"
    msg = "Int.fixed(3) fixed at 3, cannot be set at 7"
    try:
        cell.unpack(struct.pack('<I',7))
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    TYPE = Str[4].fixed('TEST')
    cell = TYPE()
    assertion('TEST', cell.repr(), 'Str fixed')
    cell.unrepr('TEST')
    assertion('TEST', cell.repr(), 'Str fixed unrepr OK')
    cell.unpack(mkbytes('TEST'))
    assertion('TEST', cell.repr(), 'Str fixed unpack OK')
    tst = "Str fixed unrepr"
    msg = "Char.fixed('T') fixed at 84, cannot be set at 66"
    try:
        cell.unrepr('BLAH')
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = "Str fixed unpack"
    msg = "Char.fixed('T') fixed at 84, cannot be set at 66"
    try:
        cell.unpack(mkbytes('BLAH'))
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    TYPE = Bits[4].fixed(1)
    TYPE._endianess = '<'
    tst = "Bits[4] fixed unpack"
    msg = "Bits[4].fixed(1) fixed at 1, cannot be set at 0"
    try:
        cell = TYPE(mkbytes('\0'))
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = "Bits[4] fixed unwork"
    msg = "Bits[4].fixed(1) fixed at 1, cannot be set at 0"
    try:
        cell = TYPE().unwork(0)
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_str_fixed_invalid(assertion):
    tst = 'Str.default invalid value'
    msg = "Str[2].default('LONG') length should be 2, cannot be set at 4"
    try:
        Str[2].default('LONG')
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = 'Str.fixed invalid value'
    msg = "Str[2].fixed('LONG') length should be 2, cannot be set at 4"
    try:
        Str[2].fixed('LONG')
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_struct_advanced(assertion):
    """ Named type """
    class TwoFieldsN(Struct):
        _fields = [
            ('a', Str['TEST']),
            ('b', Int.default(0)),
            ]
    """ Anonymous type (one-liner) """
    TwoFieldsO = Struct[[('a', Str['TEST']), ('b', Int.default(0))]]
    for TYPE in (TwoFieldsN, TwoFieldsO):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion(8, cell.packlen(), "%s.packlen"%NAME)
        data = cell.pack()
        assertion(mkbytes('TEST\0\0\0\0'),
            data,
            '%s.pack() no data'%NAME)
        assertion('TEST', str(cell['a']), '%s[a]'%NAME)
        tst = '%s.a exception'%NAME
        msg = "'%s' object has no attribute 'a'"%NAME
        try:
            assertion('TEST', cell.a,         '%s.a'%NAME)
            assertion(0,1, "%s should have raised a AttributeError"%tst)
        except AttributeError:
            e = sys.exc_info()[1]
            assertion(msg, str(e), tst)
        assertion(0,      int(cell['b']), '%s[b]'%NAME)
        assertion((cell,[]),      cell.path(),         '%s.path()'%NAME)
        assertion((cell,['a']),   cell['a'].path(),    '%s[a].path()'%NAME)
        assertion((cell,['a',1]), cell['a'][1].path(), '%s[a.1].path()'%NAME)
        data = mkbytes('FAIL\0\0\0\0')
        cell.unpack(data)
        assertion(mkbytes('FAIL\0\0\0\0'),
            cell.pack(),
            '%s.unpack().pack()'%NAME)
        cell = TYPE(data)
        assertion(mkbytes('FAIL\0\0\0\0'),
            cell.pack(),
            '%s(data).pack()'%NAME)
        cell['b'].unwork(10)
        assertion(mkbytes('FAIL\x0a\0\0\0'),
            cell.pack(),
            '%s field modification'%NAME)
        assertion({'a': 'FAIL', 'b': 10},
            cell.repr(),
            '%s struct repr'%NAME)
        cell.unrepr({'a': 'DICT', 'b': 4})
        assertion(mkbytes('DICT\x04\0\0\0'),
            cell.pack(),
            '%s struct unrepr'%NAME)
        """ Fields not mentioned are set to default """
        cell.unrepr({'a': 'TEST'})
        assertion(mkbytes('TEST\0\0\0\0'),
            cell.pack(),
            '%s struct partial unrepr'%NAME)
        cell.unwork({'a': None, 'b': None})
        assertion(mkbytes('TEST\0\0\0\0'),
            cell.pack(),
            '%s struct unwork with default values'%NAME)
        cell.unrepr({'a': 'DICT', 'b': 4})
        assertion(mkbytes('DICT\x04\0\0\0'),
            cell.pack(),
            '...')
        cell = TYPE(**cell.repr())
        assertion(mkbytes('DICT\x04\0\0\0'),
            cell.pack(),
            '...')
        cell.unwork(None)
        assertion(mkbytes('TEST\0\0\0\0'),
            cell.pack(),
            '%s struct unwork with default value'%NAME)
        tst = '%s struct invalid unrepr'%NAME
        msg = '"Keys [\'c\'] not in %s"'%NAME
        try:
            cell.unrepr({'c': 'TEST'})
            assertion(0,1, "%s should have raised a KeyError"%tst)
        except KeyError:
            e = sys.exc_info()[1]
            assertion(msg, str(e), tst)
        cell = TYPE(b=3)
        assertion(mkbytes('TEST\x03\0\0\0'),
            cell.pack(),
            '%s(b=3)'%NAME)
        cell = TYPE(a='AAAA',b=6)
        assertion(mkbytes('AAAA\x06\0\0\0'),
            cell.pack(),
            '%s(a="AAAA",b=6)'%NAME)
        cell = TYPE()
        assertion(None,
            cell._parent,
            'Struct parent')
        assertion(cell,
            cell['a']._parent,
            'Subcell parent')
    tst = 'TwoFieldsCollision() duplicate field'
    msg = "Duplicate field 'a'"
    try:
        class TwoFieldsCollision(Struct):
            _fields = [
                ('a', Str['TEST']),
                ('a', Int),
                ]
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_isdef(assertion):
    """ Shows if a cell has been defined. """
    cell = Int()
    assertion(False, cell.isdef(), 'isdef Int()')
    cell = Int(struct.pack('<I',1))
    assertion(True,  cell.isdef(), 'isdef Int(data)')
    cell = Int.default(2)()
    assertion(False, cell.isdef(), 'isdef Int.default()')
    cell = Int.fixed(2)()
    assertion(False, cell.isdef(), 'isdef Int.fixed()')
    cell = Array[Int,2]()
    assertion(True,  cell.isdef(), 'isdef Node always True)')
    cell = VarArray[Int]()
    assertion(False, cell.isdef(), 'isdef VarArray() is empty')
    cell['count'].unwork(2)
    assertion(False, cell.isdef(), 'isdef VarArray() with len but no content')

def test_struct_attributes(assertion):
    """ Struct with additional API. """
    class TwoFieldsE(AttributesElfesteem,Struct):
        _fields = [
            ('a', Str['TEST']),
            ('b', Int.default(0)),
            ('c', Int),
            ]
    class TwoFieldsS(AttributesScapy,Struct):
        _fields = [
            ('a', Str['TEST']),
            ('b', Int.default(0)),
            ('c', Int),
            ]
    for TYPE in (TwoFieldsE, TwoFieldsS):
        """ No difference here; the main difference is when a leaf is
            computed thanks to contraints. """
        NAME = TYPE.__name__
        cell = TYPE()
        assertion({'a':'TEST','b':0,'c':None}, cell.repr(), '%s default'%NAME)
        assertion('TEST',   str(cell['a']),   '%s[a]'%NAME)
        assertion('TEST',   cell.a,           '%s.a'%NAME)
        assertion(0,        int(cell['b']),   '%s[b]'%NAME)
        assertion(0,        cell.b,           '%s.b'%NAME)
        assertion(None,     cell['c'].repr(), '%s[c]'%NAME)
        assertion(None,     cell.c,           '%s.c'%NAME)
        cell.b = 10
        assertion({'a':'TEST','b':10,'c':None}, cell.repr(), '%s modif b'%NAME)
    data = mkbytes('TEST\x0a\0\0\0\x02\0\0\0')
    cell = TwoFieldsE(parent=None, content=data, start=0)
    assertion(data,                      cell.pack(), 'TwoFieldsE pack')
    assertion({'a':'TEST','b':10,'c':2}, cell.repr(), 'TwoFieldsE repr')

def test_struct_attributes_twolevels(assertion):
    """ Two levels of struct with compatibility with elfesteem. """
    class TwoLevelsE(AttributesElfesteem,Struct):
        _fields = [
            ('a', Struct[[('x', Str['TEST']), ('y', Int.default(0))]]),
            ('b', Int.default(0)),
            ]
    cell1 = TwoLevelsE()
    cell2 = TwoLevelsE()
    data = cell1.pack()
    assertion(mkbytes('TEST\0\0\0\0\0\0\0\0'),
        data,
        'TwoLevelsE.pack() no data')
    assertion('TEST', str(cell1['a']['x']), 'TwoFieldsE[a][x]')
    assertion('TEST', str(cell1['a','x']), 'TwoFieldsE[a,x]')
    assertion('TEST', cell1.a.x,            'TwoFieldsE.a.x')
    assertion(0,      int(cell1['b']),      'TwoFieldsE[b]')
    assertion(0,      cell1.b,              'TwoFieldsE.b')
    cell1.b = 10
    assertion(mkbytes('TEST\0\0\0\0\x0a\0\0\0'),
        cell1.pack(),
        'TwoLevelsE field modification')
    cell1.a.y = 8
    assertion(mkbytes('TEST\x08\0\0\0\x0a\0\0\0'),
        cell1.pack(),
        'TwoLevelsE subfield modification')
    assertion(mkbytes('TEST\0\0\0\0\0\0\0\0'),
        cell2.pack(),
        'TwoLevelsE: independency of cells')
    cell1.unrepr({'a':{'x':'FOUR','y':7},'b':4})
    assertion(mkbytes('FOUR\x07\0\0\0\x04\0\0\0'),
        cell1.pack(),
        'TwoLevelsE: unwork two levels of struct')
    subcell = cell1['a']['y']
    cell, path = subcell.path()
    assertion(subcell, cell[path], 'Subcell path and access')
    ManyLayers = Struct[[
        ('a', Array[Struct[[
            ('x',Str['A']),
            ]],1]),
        ('b', Str['Y']),
        ]]
    cell = ManyLayers()
    assertion({'a':{0:{'x':{0:65}}},'b':{0:89}},cell.work(),'Many layers, work')
    assertion({'a':[  {'x':'A'   }],'b':'Y'   },cell.repr(),'Many layers, repr')

def test_struct_attributes_virtual_fields(assertion):
    """ Virtual fields can be defined. """
    class Virtual(AttributesElfesteem,Struct):
        _fields = [
            ('a', Int.default(1)),
            ('b', Int.default(6)),
            ]
        _virtual_fields = ['c']
        def __getitem__(self, item):
            if item == 'c': return Int().unwork(self.a+self.b)
            else: return self._subcells[item]
    cell = Virtual()
    assertion(8,              cell.packlen(), "Virtual.packlen")
    assertion({'a':1, 'b':6}, cell.work(), "No virtual attribute shown")
    assertion(7,              cell.c,      "Virtual attribute")
    text = "\n".join(["<Virtual",
      "  'a' at 0x0: <Int.default(1) value=1>",
      "  'b' at 0x4: <Int.default(6) value=6>",
      "  'c': <Int value=7>",
      ">"])
    assertion(text,  cell.show(),      "StructArrayStruct.show")
    cell['c'].unwork(2)
    assertion({'a':1, 'b':6}, cell.work(), "Virtual attribute immutable")
    assertion(7,              cell.c,      "Virtual attribute immutable")

def test_struct_scapy3(assertion):
    """ Struct with scapy3 syntax (python3 only). """
    if sys.version_info[0] != 3:
        return
    class S3(StackStruct):
        a = Str[4].fixed('TEST')
        b = Int.default(0)
    NAME = S3.__name__
    cell = S3()
    assertion({'a': 'TEST', 'b': 0},   cell.repr(), '%s.repr() no data'%NAME)
    assertion(mkbytes('TEST\0\0\0\0'), cell.pack(), '%s.pack() no data'%NAME)
    tst = "%s.unrepr(...) invalid"%NAME
    msg = "Char.fixed('T') fixed at 84, cannot be set at 65"
    try:
        cell.unrepr({'a':'AAAA'})
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_complex_node(assertion):
    """ Complex node, with offsets depending on other values """
    class ComplexNode(Node):
        _layout = [
            ('a', (Int, lambda s,k:0)),
            ('b', (Int, lambda s,k:s['a'].work())),
            ]
    class ComplexNodeE(AttributesElfesteem,Node):
        _layout = [
            ('a', (Int, lambda s,k:0)),
            ('b', (Int, lambda s,k:s.a)),
            ]
    pad7 = 0x07070707
    for TYPE in (ComplexNode, ComplexNodeE):
        NAME = TYPE.__name__
        data = struct.pack("<III",4,2,3)
        cell = TYPE().unpack(data)
        assertion(8,                      cell.packlen(), "%s 1.packlen"%NAME)
        assertion({'a': 4, 'b': 2},       cell.work(), '%s 1.w'%NAME)
        assertion(struct.pack("<II",4,2), cell.pack(), '%s 1.p'%NAME)
        data = struct.pack("<III",8,2,3)
        cell = TYPE().unpack(data)
        assertion(12,                     cell.packlen(), "%s 2.packlen"%NAME)
        assertion({'a': 8, 'b': 3},       cell.work(), '%s 2.w'%NAME)
        try:
            cell.pack()
            assertion(0,1, "Should have raised a struct.error")
        except struct.error:
            pass
        assertion(struct.pack("<III",8,pad7,3), cell.pack(paddingbyte=7),
            '%s 2.p with padding'%NAME)
        cell = TYPE(a=12,b=9)
        assertion(16,                     cell.packlen(), "%s 3.packlen"%NAME)
        assertion({'a': 12, 'b': 9},      cell.work(), '%s 3.w'%NAME)
        try:
            cell.pack()
            assertion(0,1, "Should have raised a struct.error")
        except struct.error:
            pass
        assertion(struct.pack("<IIII",12,pad7,pad7,9), cell.pack(paddingbyte=7),
            '%s 3.p with padding'%NAME)
    TYPE = ComplexNode; NAME = TYPE.__name__
    data = struct.pack("<III",4,2,3)
    data7 = struct.pack("<II",4,2)
    cell = TYPE(data)
    assertion(data7,   cell.pack(),                '%s 4.p'%NAME)
    assertion(data,    cell.pack(with_holes=True), '%s 4.p with holes'%NAME)
    assertion(data7,   cell.pack(paddingbyte=7),   '%s 4.p with padding'%NAME)
    data = struct.pack("<III",8,2,3)
    data7 = struct.pack("<III",8,pad7,3)
    cell = TYPE(data)
    try:
        cell.pack()
        assertion(0,1, "%s 5.p should have raised a struct.error"%NAME)
    except struct.error:
        pass
    assertion(data,    cell.pack(with_holes=True), '%s 5.p with holes'%NAME)
    assertion(data7,   cell.pack(paddingbyte=7),   '%s 5.p with padding'%NAME)
    TYPE = ComplexNodeE; NAME = TYPE.__name__
    data = struct.pack("<III",4,2,3)
    cell = TYPE(data)
    assertion(data,    cell.pack(),                '%s 4.p'%NAME)
    assertion(data,    cell.pack(paddingbyte=7),   '%s 4.p with padding'%NAME)
    data = struct.pack("<III",8,2,3)
    cell = TYPE(data)
    assertion(data,    cell.pack(),                '%s 5.p'%NAME)
    assertion(data,    cell.pack(paddingbyte=7),   '%s 5.p with padding'%NAME)

def test_at_offset(assertion):
    class NO(AttributesElfesteem,Node):
        _ptrsize = 32
        _endianess = '<'
        _layout = [
            ('pos',      (Ptr, lambda s,k:0)),
            ('data',     (Data, lambda s,k:s.pos)),
            ]
    data = mkbytes('\x06\0\0\0AACDEF')
    cell = NO(data)
    assertion(len(data), cell.packlen(), "NO.packlen")
    assertion([slice(4,6)],
        cell.not_parsed.ranges,
        "NO(data) not everything parsed")
    assertion(data,
        cell.pack(),
        'NO(data).pack()')
    cell = NO().unpack(data)
    assertion(mkbytes('\x06\0\0\0\2\2CDEF'),
        cell.pack(paddingbyte=2),
        'NO().unpack(data).pack(paddingbyte=2)')
    class NP(AttributesElfesteem,Node):
        _layout = [
            ('pos',      (Int,    lambda s,k:0)),
            ('data',     (Int,    lambda s,k:s.pos)),
            ('val',      (Str[2], lambda s,k:s.data)),
            ]
    data = mkbytes('\x06\0\0\0AA\x04\0\0\0')
    cell = NP(data)
    assertion(data,
        cell.pack(),
        'NP(data).pack()')
    cell['val'].unrepr('BB')
    assertion(mkbytes('\x06\0\0\0BB\x04\0\0\0'),
        cell.pack(),
        'NP(modified data).pack()')
    data = mkbytes('\x05\0\0\0A\x04\0\0\0')
    cell = NP(data)
    assertion(data,
        cell.pack(),
        'NP(data).pack() with coherent overlap')
    cell['val'].unrepr('BB')
    tst = 'NP(data).pack() with incoherent overlap'
    msg = "Overlapping chunks at 5"
    try:
        cell.pack()
        assertion(0,1, "%s should have raised a CellError"%tst)
    except ValueError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    assertion(mkbytes('\x05\0\0\0BB\0\0\0'),
        cell.pack(overwrite=True),
        'NP(data).pack() with incoherent overlap')

def test_bitfields(assertion):
    """ Struct with bitfields. """
    class IPaddr(Int):
        def repr2work(cls, val):
            if isinstance(val, str):
                val = sum([int(v)<<(8*(3-i)) for i,v in enumerate(val.split('.'))])
            return val
        repr2work = classmethod(repr2work)
        def work2repr(cls, val):
            if val is not None:
                val = '%d.%d.%d.%d'%struct.unpack('BBBB',struct.pack('>I',val))
            return val
        work2repr = classmethod(work2repr)
    class IP(Struct):
        _endianess = '>'
        _fields = [
            ('version',     Bits[4] .default(4)),
            ('ihl',         Bits[4] .default(5)),
            ('tos',         Byte    .default(0)),
            ('len',         Short   .default(0)),
            ('id',          Short   .default(0)),
            ('flags',       Bits[3] .default(0)),
            ('fragofs',     Bits[13].default(0)),
            ('ttl',         Byte    .default(64)),
            ('proto',       Byte    .default(0)),
            ('cksum',       Short   .default(0)),
            ('src',         IPaddr  .default('127.0.0.1')),
            ('dst',         IPaddr  .default('127.0.0.1')),
            ]
    data = mkbytes('\x45\0\0\0\0\0\0\0@\0\0\0\x7f\0\0\x01\x7f\0\0\x01')
    cell = IP()
    assertion(20, cell.packlen(), "IP.packlen")
    assertion(data, cell.pack(), 'IP: default value')
    data = mkbytes('\x45\0\0\x14\0\x01@\0@\0<\xe7\x7f\0\0\x01\x7f\0\0\x01')
    cell.unpack(data)
    assertion(data, cell.pack(), 'IP.unpack(data)')
    cell = IP(data)
    assertion(data, cell.pack(), 'IP(data)')

def test_struct_equal(assertion):
    """ Two cells have equal values. """
    cntnt = lambda _: dict([(k,v._content) for k,v in _._subcells.items()])
    rule_fail = lambda cell: "\n".join(["<%s"%NAME,
        "  'a' at 0x0: <Int.default(0) value=%d>"%cell['a'],
        "  'b' at 0x4: <Int.default(0) value=%d>"%cell['b'],
        "> does not satisfy RuleEqual('a', 'b')"])
    class EqualCell(Struct):
        _fields = [
            ('a', Int.default(0)),
            ('b', Int.default(0)),
            ]
        _rules = [
            RuleEqual('a', 'b'),
            ]
    TYPE = EqualCell
    NAME = TYPE.__name__
    cell = TYPE()
    assertion({'a':None, 'b':None}, cntnt(cell), "%s().cntnt"%NAME)
    assertion({'a':0,    'b':0},    cell.work(), "%s().work()"%NAME)
    assertion(None,                 cell.check(),"%s().chk OK"%NAME)
    cell = TYPE(a=2)
    assertion({'a':2,    'b':None}, cntnt(cell), "%s(a=2).cntnt"%NAME)
    assertion({'a':2,    'b':2},    cell.work(), "%s(a=2).work()"%NAME)
    assertion(None,                 cell.check(),"%s(a=2).chk OK"%NAME)
    cell = TYPE(b=2)
    assertion({'a':None, 'b':2},    cntnt(cell), "%s(b=2).cntnt"%NAME)
    assertion({'a':2,    'b':2},    cell.work(), "%s(b=2).work()"%NAME)
    assertion(None,                 cell.check(),"%s(b=2).chk OK"%NAME)
    cell = TYPE(a=1,b=2)
    assertion({'a':1,    'b':2},    cntnt(cell), "%s(a=1,b=2).cntnt"%NAME)
    assertion({'a':1,    'b':2},    cell.work(), "%s(a=1,b=2).work()"%NAME)
    assertion(rule_fail(cell),      cell.check(),"%s(a=1,b=2).chk KO"%NAME)
    cell = TYPE(mkbytes('\0'*8))
    assertion({'a':0,    'b':0},    cntnt(cell), "%s('\0'*8).cntnt"%NAME)
    assertion({'a':0,    'b':0},    cell.work(), "%s('\0'*8).work()"%NAME)
    assertion(None,                 cell.check(),"%s('\0'*8).chk OK"%NAME)
    cell = TYPE(mkbytes('A'+'\0'*7))
    assertion({'a':65,   'b':0},    cntnt(cell), "%s(A+0*7).cntnt"%NAME)
    assertion({'a':65,   'b':0},    cell.work(), "%s(A+0*7).work()"%NAME)
    assertion(rule_fail(cell),      cell.check(),"%s(A+0*7).chk KO"%NAME)
    cell = TYPE().unwork({'a':2})
    assertion({'a':2,    'b':None}, cntnt(cell), "%s({'a':2}).cntnt"%NAME)
    assertion({'a':2,    'b':2},    cell.work(), "%s({'a':2}).work()"%NAME)
    assertion(None,                 cell.check(),"%s({'a':2}).chk OK"%NAME)
    cell = TYPE().unwork({'a':2,'b':2})
    assertion({'a':2,    'b':2},    cntnt(cell), "%s({a2,b2}).cntnt"%NAME)
    assertion({'a':2,    'b':2},    cell.work(), "%s({a2,b2}).work()"%NAME)
    assertion(None,                 cell.check(),"%s({a2,b2}).chk OK"%NAME)
    cell = TYPE().unwork({'a':1,'b':2})
    assertion({'a':1,    'b':2},    cntnt(cell), "%s({a1,b2}).cntnt"%NAME)
    assertion({'a':1,    'b':2},    cell.work(), "%s({a1,b2}).work()"%NAME)
    assertion(rule_fail(cell),      cell.check(),"%s({a1,b2}).chk KO"%NAME)
    def cntnt(cell):
        if hasattr(cell, '_content'): return cell._content
        return dict([(k,cntnt(v)) for k,v in cell._subcells.items()])
    rule_fail = lambda cell: "\n".join(["<%s"%NAME,
        "  'a' at 0x0: <unnamed Struct",
        "    'x' at 0x0: <Int.default(0) value=%d>"%cell['a']['x'],
        "  >",
        "  'b' at 0x4: <Int.default(0) value=%d>"%cell['b'],
        "> does not satisfy RuleEqual('a.x', 'b')"])
    class EqualSubCell(Struct):
        _fields = [
            ('a', Struct[[('x',Int.default(0))]]),
            ('b', Int.default(0)),
            ]
        _rules = [
            RuleEqual('a.x', 'b'),
            ]
    TYPE = EqualSubCell
    NAME = TYPE.__name__
    cell = TYPE()
    assertion(struct.pack('<II',0,0),   cell.pack(),"%s().pack()"%NAME)
    assertion({'a':{'x':0},   'b':0},   cell.work(),"%s().work()"%NAME)
    assertion({'a':{'x':None},'b':None},cntnt(cell),"%s().cntnt"%NAME)
    assertion(None,                    cell.check(),"%s().chk OK"%NAME)
    cell = TYPE(a={'x':2})
    assertion({'a':{'x':2},   'b':None},cntnt(cell),"%s(a.x=2).cntnt"%NAME)
    assertion({'a':{'x':2},   'b':2},   cell.work(),"%s(a.x=2).work()"%NAME)
    assertion(None,                    cell.check(),"%s(a.x=2).chk OK"%NAME)
    cell = TYPE(b=2)
    assertion({'a':{'x':None},'b':2},   cntnt(cell),"%s(b=2).cntnt"%NAME)
    assertion({'a':{'x':2},   'b':2},   cell.work(),"%s(b=2).work()"%NAME)
    assertion(None,                    cell.check(),"%s(b=2).chk OK"%NAME)
    cell = TYPE(a={'x':1},b=2)
    assertion({'a':{'x':1},   'b':2},   cntnt(cell),"%s(a.x=1,b=2).cntnt"%NAME)
    assertion({'a':{'x':1},   'b':2},   cell.work(),"%s(a.x=1,b=2).work()"%NAME)
    assertion(struct.pack('<II',1,2),   cell.pack(),"%s(a.x=1,b=2).pack()"%NAME)
    assertion(rule_fail(cell),         cell.check(),"%s(a.x=1,b=2).chk KO"%NAME)
    cell = TYPE(mkbytes('\0'*8))
    assertion({'a':{'x':0},   'b':0},   cell.work(),"%s('\0'*8).work()"%NAME)
    assertion(struct.pack('<II',0,0),   cell.pack(),"%s('\0'*8).pack()"%NAME)
    assertion(None,                    cell.check(),"%s('\0'*8).chk OK"%NAME)
    cell = TYPE(mkbytes('A'+'\0'*7))
    assertion({'a':{'x':65},  'b':0},   cntnt(cell),"%s(A+0*7).cntnt"%NAME)
    assertion({'a':{'x':65},  'b':0},   cell.work(),"%s(A+0*7).work()"%NAME)
    assertion(rule_fail(cell),         cell.check(),"%s(A+0*7).chk KO"%NAME)

def test_struct_equal_pairs(assertion):
    """ Two pairs of cells have equal values. """
    cntnt = lambda _: dict([(k,v._content) for k,v in _._subcells.items()])
    rule_fail = lambda cell: "\n".join(["<%s"%NAME,
        "  'a' at 0x0: <Int.default(0) value=%d>"%cell['a'],
        "  'b' at 0x4: <Int.default(0) value=%d>"%cell['b'],
        "> does not satisfy RuleEqual(['a'], ['b'])"])
    class EqualPairs(Struct):
        _fields = [
            ('a', Int.default(0)),
            ('b', Int.default(0)),
            ('c', Int.default(0)),
            ('d', Int.default(0)),
            ]
        _rules = [
            RuleEqual('a', 'b'),
            RuleEqual('c', 'd'),
            ]
    TYPE = EqualPairs
    NAME = TYPE.__name__
    cell = TYPE(a=2)
    assertion({'a':2,'b':2,'c':0,'d':0}, cell.work(), "%s(a=2)"%NAME)
    cell = TYPE(a=2,c=3)
    assertion({'a':2,'b':2,'c':3,'d':3}, cell.work(), "%s(a=2,c=3)"%NAME)
    cell = TYPE(a=2,b=4,c=3)
    assertion({'a':2,'b':4,'c':3,'d':3}, cell.work(), "%s(a=2,b=4,c=3)"%NAME)

def test_struct_equal_three(assertion):
    """ Three cells have equal values, only two rules. """
    cntnt = lambda _: dict([(k,v._content) for k,v in _._subcells.items()])
    rule_fail = lambda cell, rule: "\n".join(["<%s"%NAME,
        "  'a' at 0x0: <Int.default(0) value=%d>"%cell['a'],
        "  'b' at 0x4: <Int.default(1) value=%d>"%cell['b'],
        "  'c' at 0x8: <Int.default(2) value=%d>"%cell['c'],
        "> does not satisfy %s"%cell._rules[rule]])
    class ThreeCells1(Struct):
        _fields = [
            ('a', Int.default(0)),
            ('b', Int.default(1)),
            ('c', Int.default(2)),
            ]
        _rules = [
            RuleEqual('a', 'b', 'c'),
            ]
    """ Three cells have equal values, all three rules. """
    class ThreeCells2(Struct):
        _fields = [
            ('a', Int.default(0)),
            ('b', Int.default(1)),
            ('c', Int.default(2)),
            ]
        _rules = [
            RuleEqual('a', 'b'),
            RuleEqual('a', 'c'),
            RuleEqual('b', 'c'),
            ]
    for TYPE in (ThreeCells1, ThreeCells2):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion({'a':None,'b':None,'c':None},cntnt(cell),"%s().cntnt"%NAME)
        assertion({'a':0,   'b':1,   'c':2},   cell.work(),"%s().work()"%NAME)
        assertion(struct.pack('<III',0,1,2),   cell.pack(),"%s().pack()"%NAME)
        assertion(rule_fail(cell,0),          cell.check(),"%s().chk KO"%NAME)
        cell = TYPE(a=9)
        assertion({'a':9,   'b':None,'c':None},cntnt(cell),"%s(a9).cntnt"%NAME)
        assertion({'a':9,   'b':9,   'c':9},   cell.work(),"%s(a9).work()"%NAME)
        assertion(None,                       cell.check(),"%s(a9).chk OK"%NAME)
        cell = TYPE(b=9)
        assertion({'a':None,'b':9,   'c':None},cntnt(cell),"%s(b9).cntnt"%NAME)
        assertion({'a':9,   'b':9,   'c':9},   cell.work(),"%s(b9).work()"%NAME)
        assertion(None,                       cell.check(),"%s(b9).chk KO"%NAME)
        """ Inconsistent content: 'a' set to default """
        cell = TYPE(b=8,c=9)
        assertion({'a':None,'b':8, 'c':9},  cntnt(cell),"%s(b8,c9).cntnt"%NAME)
        assertion({'a':0,   'b':8, 'c':9},  cell.work(),"%s(b8,c9).work()"%NAME)
        assertion(rule_fail(cell,0),       cell.check(),"%s(b8,c9).chk KO"%NAME)

def test_struct_attributes_elfesteem(assertion):
    """ Struct with additional API to make it compatible with elfesteem.
        The difference with scapy is cell.b when undefined: computed by rules
    """
    cntnt = lambda _: dict([(k,v._content) for k,v in _._subcells.items()])
    class EqualCellE(AttributesElfesteem,Struct):
        _fields = [
            ('a', Int.default(0)),
            ('b', Int),
            ]
        _rules = [
            RuleEqual('a', 'b'),
            ]
    TYPE = EqualCellE
    NAME = TYPE.__name__
    cell = TYPE(a=2)
    assertion({'a':2,    'b':None}, cntnt(cell), "%s(a=2).cntnt"%NAME)
    assertion({'a':2,    'b':2},    cell.work(), "%s(a=2).work()"%NAME)
    assertion(None,                 cell.check(),"%s(a=2).chk OK"%NAME)
    assertion(2,             cell['a'].work(),   '%s(a=2)[a]'%NAME)
    assertion(2,             cell.a,             '%s(a=2).a'%NAME)
    assertion(2,             cell['b'].work(),   '%s(a=2)[b]'%NAME)
    assertion(2,             cell.b,             '%s(a=2).b'%NAME)
    cell.b = 9
    assertion({'a':2,    'b':9},    cell.work(), "%s(a=2).b=9"%NAME)
    cell = TYPE()
    assertion({'a':None, 'b':None}, cntnt(cell), "%s().cntnt"%NAME)
    assertion({'a':0,    'b':0},    cell.work(), "%s().work()"%NAME)
    cell.b = 9
    assertion({'a':None, 'b':9},    cntnt(cell), "%s().b=9.cntnt"%NAME)
    assertion({'a':9,    'b':9},    cell.work(), "%s().b=9.work()"%NAME)

def test_struct_attributes_scapy(assertion):
    """ Struct with additional API to make it compatible with scapy2.
        The difference with elfesteem is cell.b when undefined: None
    """
    cntnt = lambda _: dict([(k,v._content) for k,v in _._subcells.items()])
    class EqualCellS(AttributesScapy,Struct):
        _fields = [
            ('a', Int.default(0)),
            ('b', Int),
            ]
        _rules = [
            RuleEqual('a', 'b'),
            ]
    TYPE = EqualCellS
    NAME = TYPE.__name__
    cell = TYPE(a=2)
    assertion({'a':2,    'b':None}, cntnt(cell), "%s(a=2).cntnt"%NAME)
    assertion({'a':2,    'b':2},    cell.work(), "%s(a=2).work()"%NAME)
    assertion(None,                 cell.check(),"%s(a=2).chk OK"%NAME)
    assertion(2,             cell['a'].work(),   '%s(a=2)[a]'%NAME)
    assertion(2,             cell.a,             '%s(a=2).a'%NAME)
    assertion(2,             cell['b'].work(),   '%s(a=2)[b]'%NAME)
    assertion(None,          cell.b,             '%s(a=2).b'%NAME)
    cell.b = 9
    assertion({'a':2,    'b':9},    cell.work(), "%s(a=2).b=9"%NAME)

def test_struct_equal_string(assertion):
    """ Two cells have equal values: strings. """
    class EqualString(Struct):
        _fields = [
            ('a', Str[4].default('ABCD')),
            ('b', Str[4].default('WXYZ')),
            ]
        _rules = [
            RuleEqual('a', 'b'),
            ]
    TYPE = EqualString
    NAME = TYPE.__name__
    cell = TYPE()
    try:
        assertion({'a':'ABCD', 'b':'WXYZ'}, cell.repr(), "%s().repr()"%NAME)
    except AttributeError:
        """
        Currently does not work: RuleManager only works for Leaf, and Str
        is an array, therefore a Node.
        """

def test_union(assertion):
    """ Simple union """
    class UY(Union):
        """ Empty _options, which is populated later. """
        _options = []
    class UG0(Struct):
        _fields = [
            ('selector', Byte.fixed(0)),
            ('content',  Byte),
            ]
    UY._options.append(UG0)
    class UG1(Struct):
        _fields = [
            ('selector', Byte.fixed(1)),
            ('content',  Int),
            ]
    UY._options.append(UG1)
    class UG2(UG1):
        _fields = [
            ('selector', Byte.fixed(2)),
            ('content',  Int),
            ]
    class UGX(Array[Byte,5]):
        pass
    UY._options.append(UGX)
    class UG(Union):
        """ In this case, the union is defined after its possibilities. """
        _options = [UG0, UG1, UG2]
    class UX(Union):
        _options = [UG0, UG1, UGX]
    for TYPE in (UG, UX, UY):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion(None, cell.work(), '%s work default'%NAME)
        assertion(None, cell.pack(), '%s pack default'%NAME)
        data = struct.pack("<BB",0,24)
        cell = TYPE(data)
        assertion(TYPE._options[0], cell._wrapped.__class__,'%s/0 option'%NAME)
        assertion(24, cell['content'].work(),               '%s/0 content'%NAME)
        assertion(data,                        cell.pack(), '%s/0 pack'%NAME)
        assertion({'selector':0,'content':24}, cell.repr(), '%s/0 repr'%NAME)
        cell1 = TYPE()
        cell2 = cell1.unpack(data)
        assertion(TYPE, cell1.__class__, 'alternate syntax')
        assertion(TYPE, cell2.__class__, 'alternate syntax')
        assertion(data, cell1.pack(), 'alternate syntax')
        assertion(data, cell2.pack(), 'alternate syntax')
        data = struct.pack("<BI",1,24)
        cell = TYPE(data)
        assertion(TYPE._options[1], cell._wrapped.__class__,'%s/1 option'%NAME)
        assertion(24, cell['content'].work(),               '%s/1 content'%NAME)
        assertion(data,                        cell.pack(), '%s/1 pack'%NAME)
        assertion({'selector':1,'content':24}, cell.repr(), '%s/1 repr'%NAME)
        data = struct.pack("<BI",2,24)
        cell = TYPE(data)
        assertion(data,                        cell.pack(), '%s/2 pack'%NAME)
        if   TYPE == UG: value = {'selector':2,'content':24}
        else:            value = [2, 24, 0, 0, 0]
        assertion(value,                       cell.repr(), '%s/2 repr'%NAME)
        data = struct.pack("<BI",1,24)
        cell.unpack(data)
        assertion(data, cell.pack(), '%s/2 then 1'%NAME)
        data = struct.pack("BB",0,24)
        cell = TYPE().unwork(TYPE._options[0](content=24))
        assertion(data, cell.pack(), '%s.unwork(TypedStruct0)'%NAME)
        cell.unwork(None)
        assertion(None, cell.work(), '%s work default'%NAME)
        data = mkbytes("INVALID")
        cell.unwork(data)
        assertion(data, cell.work(), '%s work fallback'%NAME)
        data = Leaf()
        try:
            cell = TYPE().unwork(data)
            assertion(0,1, "Should have raised a TypeError")
        except TypeError:
            pass
        cell = TYPE().unwork({'selector':1, 'content':12})
        data = struct.pack("<BI",1,12)
        assertion(data, cell.pack(), '%s.unwork(option 1)'%NAME)
        data = struct.pack("<BI",3,24)
        cell = TYPE(data)
        assertion(data, cell.pack(), '%s/3 pack'%NAME)
        cell = TYPE().unrepr({'selector':1, 'content':12})
    class SU(Struct):
        _fields = [
            ('ug', UG),
            ('ux', UX),
            ]
    data = struct.pack("<BIBI",1,5,2,7)
    xxxx = {'ug': {'content': 5, 'selector': 1}, 'ux': [2, 7, 0, 0, 0]}
    cell = SU(data)
    assertion(xxxx, cell.repr(), "Struct[Union,Union] unpack")
    cell = SU(**xxxx)
    assertion(xxxx, cell.repr(), "Struct[Union,Union] unrepr")

def test_union_elfesteem(assertion):
    """ Generic union type, with elfesteem API """
    class UE0(Struct):
        _fields = [
            ('selector', Byte.fixed(0)),
            ('content',  Byte),
            ]
    class UE1(Struct):
        _fields = [
            ('selector', Byte.fixed(1)),
            ('content',  Int),
            ]
    class UE2(Struct):
        _fields = [
            ('selector', Byte.fixed(2)),
            ('other',  Int),
            ]
    class UnionElfesteem(AttributesElfesteem,Union):
        _options = [UE0, UE1, UE2]
    TYPE = UnionElfesteem
    NAME = TYPE.__name__
    cell = TYPE(struct.pack("<BI",1,24))
    assertion(24,
        cell.content,
        '%s option 1, has content as attribute'%NAME)
    cell = TYPE(struct.pack("<BI",2,10))
    assertion(10,
        cell.other,
        '%s option 2, has other as attribute'%NAME)
    tst = '%s option 2, does not have content'%NAME
    msg = "'content'"
    try:
        cell.content
        assertion(0,1, "%s should have raised a KeyError"%tst)
    except KeyError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_array_variable_length(assertion):
    class IntVarArrayA(VarArray):
        _type = Int
    IntVarArrayB = VarArray[Int]
    for TYPE in (IntVarArrayA, IntVarArrayB):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion([],        cell.repr(),        '%s.repr() no data'%NAME)
        assertion(None,      cell['count'].work(), '%s.len no data'%NAME)
        val = [0,1]
        data = struct.pack("<%dI"%len(val),*val)
        cell.unrepr(val)
        assertion(val,  cell.repr(),    '%s(array%d).repr'%(NAME,len(val)))
        assertion(data, cell.pack(),    '%s(array%d).pack'%(NAME,len(val)))
        assertion(1,    cell[1].repr(), '%s(array%d)[1].repr'%(NAME,len(val)))
        assertion(len(val),cell['count'].work(),'%s(array%d).len'%(NAME,len(val)))
        val = [0,1,2,3]
        data = struct.pack("<%dI"%len(val),*val)
        tst = 'Unrepr array with too many elements'
        msg = "%s length should be 2, cannot be set at 4"%NAME
        try:
            cell.unrepr(val)
            assertion(0,1, "%s should have raised a CellError"%tst)
        except CellError:
            e = sys.exc_info()[1]
            assertion(msg, str(e), tst)
        """ re-initialize """
        cell.unrepr(None)
        cell.unrepr(val)
        assertion(val,  cell.repr(),    '%s(array%d).repr'%(NAME,len(val)))
        assertion(data, cell.pack(),    '%s(array%d).pack'%(NAME,len(val)))
        assertion(1,    cell[1].repr(), '%s(array%d)[1].repr'%(NAME,len(val)))
        assertion(len(val),cell['count'].work(),'%s(array%d).len'%(NAME,len(val)))
        tst = 'Change length of defined array'
        msg = "%s length is 4, cannot be set at 3"%NAME
        try:
            cell['count'].unwork(3)
            assertion(0,1, "%s should have raised a CellError"%tst)
        except CellError:
            e = sys.exc_info()[1]
            assertion(msg, str(e), tst)
        cell = TYPE()
        cell['count'].unwork(3)
        assertion([], cell.repr(), '%s(len=3).repr'%NAME)
        cell.unpack(data)
        assertion([0,1,2],  cell.repr(),    '%s(array%d).repr'%(NAME,len(val)))
        cell = TYPE()
        cell.unpack(data, size=12)
        assertion([0,1,2],   cell.repr(), '%s.unpack(size=12)'%NAME)
        cell.unpack(data, size=12)
        tst = "%s.unpack with packlen 7"%NAME
        msg = "%s unpack wrong packlen 8 != 7"%NAME
        try:
            cell.unpack(data, size=7)
            assertion(0,1, "%s should have raised a ValueError"%tst)
        except ValueError:
            e = sys.exc_info()[1]
            assertion(msg, str(e), tst)
        assertion(data[:7],  cell.repr(), '%s.unpack(size=7)'%NAME)
        tst = "%s.unpack with packlen 6"%NAME
        msg = "%s unpack wrong packlen 8 != 6"%NAME
        try:
            cell = TYPE().unpack(data, size=6)
        except ValueError:
            e = sys.exc_info()[1]
            assertion(msg, str(e), tst)
        """ isdef and state """
        cell = TYPE()
        assertion(False,       cell.isdef(), '%s.isdef() no data'%NAME)
        assertion('undefined', cell.state(), '%s.state() no data'%NAME)
        cell = TYPE().unrepr([0,1,2])
        assertion(True,        cell.isdef(), '%s(array3).isdef()'%NAME)
        assertion('defined',   cell.state(), '%s(array3).state()'%NAME)
        cell = TYPE().unrepr([])
        assertion(True,        cell.isdef(), '%s(array0).isdef()'%NAME)
        assertion('defined',   cell.state(), '%s(array0).state()'%NAME)
        cell = TYPE()
        try:
            cell.unpack(data, size=7)
        except ValueError:
            pass
        assertion(False,       cell.isdef(), '%s.unpack(size=7).isdef()'%NAME)
        assertion('invalid',   cell.state(), '%s.unpack(size=7).state()'%NAME)
        cell = TYPE()
        cell['count'].unwork(3)
        assertion(False,       cell.isdef(), '%s.isdef(len=3) no data'%NAME)
        assertion('virtual',   cell.state(), '%s.state(len=3) no data'%NAME)
        """ Not too slow even when len is way too big """
        cell = TYPE()
        cell['count'].unwork(1<<30)
        assertion(0,     len(cell._wrapped._subcells), '%s(len=1<<30).sc'%NAME)
        assertion(1<<30, cell['count'].work(), '%s(len=1<<30).len'%NAME)
        assertion(0,     len(cell.repr()), '%s(len=1<<30).repr'%NAME)
        """ packlen """
        cell = TYPE(data)
        assertion(data,            cell.pack(), "%s pack 16"%NAME)
        assertion(16,   cell['packlen'].work(), "%s packlen 16"%NAME)
        cell = TYPE()
        assertion(None, cell['packlen'].work(), "%s packlen None"%NAME)
        cell['packlen'].unwork(8)
        assertion(8,    cell['packlen'].work(), "%s packlen 8"%NAME)
        cell.unpack(data)
        assertion(data[:8], cell.pack(), "%s unpack packlen=8"%NAME)
        tst = 'Change packlen of defined array'
        msg = "%s bytelength is 8, cannot be set at 9"%NAME
        try:
            cell['packlen'].unwork(9)
            assertion(0,1, "%s should have raised a CellError"%tst)
        except CellError:
            e = sys.exc_info()[1]
            assertion(msg, str(e), tst)
        """ Unpack when packlen is not a multiple of subcell size """
        cell = TYPE()
        cell['packlen'].unwork(9)
        assertion(9,           cell['packlen'].work(), "%s packlen 9"%NAME)
        try:
            cell.unpack(data)
        except ValueError:
            pass
        assertion(9,           cell['packlen'].work(), "%s packlen 9->12"%NAME)
        assertion(data[:9],    cell.pack(),  "%s packlen=9 pack"%NAME)
        assertion('invalid',   cell.state(), '%s packlen 9 state'%NAME)

def test_array_struct(assertion):
    """ Struct with a Var Array of Struct : check offset computation! """
    class S2(Struct):
        _fields = [('a',Byte),('b',Byte)]
    class StructArrayStruct(Struct):
        _fields = [
            ('x',Int),
            ('y',VarArray[S2]),
            ]
    cell = StructArrayStruct()
    cell['y']['count'].unwork(2)
    cell['y'].unrepr([{'a':0,'b':1},{'a':2,'b':3}])
    text = "\n".join(["<StructArrayStruct",
      "  'x' at 0x0: <Int value=None>",
      "  'y' at 0x4: <VarArray[S2] wrapped=<Array[S2,2]",
      "      0 at 0x4: <S2",
      "        'a' at 0x4: <Byte value=0>",
      "        'b' at 0x5: <Byte value=1>",
      "      >",
      "      1 at 0x6: <S2",
      "        'a' at 0x6: <Byte value=2>",
      "        'b' at 0x7: <Byte value=3>",
      "      >",
      "    >>",
      ">"])
    assertion(text,  cell.show(),      "StructArrayStruct.show")
    cell = StructArrayStruct().unpack(struct.pack("<IBBBB",100,1,2,3,4))
    text = "\n".join(["<StructArrayStruct",
      "  'x' at 0x0: <Int value=100>",
      "  'y' at 0x4: <VarArray[S2] wrapped=<Array[S2,0]",
      "      0 at 0x4: <S2",
      "        'a' at 0x4: <Byte value=1>",
      "        'b' at 0x5: <Byte value=2>",
      "      >",
      "      1 at 0x6: <S2",
      "        'a' at 0x6: <Byte value=3>",
      "        'b' at 0x7: <Byte value=4>",
      "      >",
      "    >>",
      ">"])
    assertion(text,  cell.show(),      "StructArrayStruct.unpack.show")

def test_array_length_constraint(assertion):
    class ALX(Struct):
        _fields = [
            ('len',      Int),
            ('array',    VarArray[Byte.default(0)]),
            ]
        _rules = [
            RuleEqual('len', 'array.count'),
            ]
        _test_empty_repr = {'len':None,'array':[]}
        _test_empty_pack = None
    class AL4(Struct):
        _fields = [
            ('len',      Int.default(4)),
            ('array',    VarArray[Byte.default(0)]),
            ]
        _rules = [
            RuleEqual('len', 'array.count'),
            ]
        _test_empty_repr = {'len':4,'array':[]}
        _test_empty_pack = struct.pack('<I',4)
    rule_fail = lambda cell: "\n".join(["<%s"%NAME,
        "    'len' at 0x0: <%s value=7>"%cell['len'].__class__.__name__,
        "  'array' at 0x4: <VarArray[Byte.default(0)] wrapped=<Array[Byte.default(0),2]",
        "      0 at 0x4: <Byte.default(0) value=8>",
        "      1 at 0x5: <Byte.default(0) value=9>",
        "    >>",
        "> does not satisfy RuleEqual('len', 'array.count')"])
    for TYPE in (ALX, AL4):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion(TYPE._test_empty_repr,   cell.repr(), '%s().r'%NAME)
        assertion(TYPE._test_empty_pack,   cell.pack(), '%s().p'%NAME)
        assertion(None,                    cell.check(),'%s().c'%NAME)
        cell = TYPE(len=0)
        assertion({'len':0,'array':[]},    cell.repr(), '%s(len=O).r'%NAME)
        assertion(struct.pack('<I',0),     cell.pack(), '%s(len=0).p'%NAME)
        assertion(None,                    cell.check(),'%s(len=0).c'%NAME)
        cell = TYPE(len=2)
        assertion({'len':2,'array':[]},     cell.repr(), '%s(len=2).r'%NAME)
        assertion(struct.pack('<I',2),      cell.pack(), '%s(len=2).p'%NAME)
        assertion(None,                     cell.check(),'%s(len=2).c'%NAME)
        cell['array'].unrepr([0,7])
        assertion({'len':2,'array':[0,7]},  cell.repr(), '%s(l=2)[0,7].r'%NAME)
        assertion(struct.pack('<IBB',2,0,7),cell.pack(), '%s(l=2)[0,7].p'%NAME)
        assertion(None,                     cell.check(),'%s(l=2)[0,7].c'%NAME)
        cell = TYPE(len=2,array=[8,9])
        assertion({'len':2,'array':[8,9]},  cell.repr(), '%s(l=2,[8,9]).r'%NAME)
        assertion(struct.pack('<IBB',2,8,9),cell.pack(), '%s(l=2,[8,9]).p'%NAME)
        assertion(None,                     cell.check(),'%s(l=2,[8,9]).c'%NAME)
        cell = TYPE(array=[8,9])
        assertion({'len':2,'array':[8,9]},  cell.repr(), '%s(a=[8,9]).r'%NAME)
        assertion(struct.pack('<IBB',2,8,9),cell.pack(), '%s(a=[8,9]).p'%NAME)
        assertion(None,                     cell.check(),'%s(a=[8,9]).c'%NAME)
        cell = TYPE(len=7,array=[8,9])
        assertion({'len':7,'array':[8,9]},  cell.repr(), '%s(l=7,[8,9]).r'%NAME)
        assertion(struct.pack('<IBB',7,8,9),cell.pack(), '%s(l=7,[8,9]).p'%NAME)
        assertion(rule_fail(cell),          cell.check(),'%s(l=7,[8,9]).c'%NAME)
        data = struct.pack('<IBBBBBB',4,0,1,2,3,4,5)
        cell = TYPE(data)
        assertion({'len':4,'array':[0,1,2,3]},  cell.repr(), '%s(data).r'%NAME)
        assertion(data[:8],                     cell.pack(), '%s(data).p'%NAME)
        assertion(None,                         cell.check(),'%s(data).c'%NAME)
        assertion([slice(8,10)], cell.not_parsed.ranges, '%s(data).x'%NAME)
        cell = TYPE()
        cell['array'].unrepr([0,5,0,0])
        assertion({'len':4,'array':[0,5,0,0]}, cell.repr(),'%s()[0,5,0,0]'%NAME)
        cell = TYPE()
        cell['array'].unrepr([0,5,0])
        assertion({'len':3,'array':[0,5,0]},   cell.repr(),'%s()[0,5,0]'%NAME)

def test_array_packlen_constraint(assertion):
    class APX(Struct):
        _fields = [
            ('len',      Int),
            ('array',    VarArray[Int.default(0)]),
            ]
        _rules = [
            RuleEqual('len', 'array.packlen'),
            ]
    rule_fail = lambda cell: "\n".join(["<%s"%NAME,
        "    'len' at 0x0: <%s value=%d>"%(cell['len'].__class__.__name__,cell['len'].work()),
        "  'array' at 0x4: <VarArray[Int.default(0)] wrapped=<Array[Int.default(0),2]",
        "      0 at 0x4: <Int.default(0) value=%d>"%cell['array',0].work(),
        "      1 at 0x8: <Int.default(0) value=%d>"%cell['array',1].work(),
        "    >>",
        "> does not satisfy RuleEqual('len', 'array.packlen')"])
    TYPE = APX
    NAME = TYPE.__name__
    cell = TYPE()
    assertion({'len':None,'array':[]}, cell.repr(), '%s().r'%NAME)
    assertion(None,                    cell.pack(), '%s().p'%NAME)
    assertion(None,                    cell.check(),'%s().c'%NAME)
    cell = TYPE(len=0)
    assertion({'len':0,'array':[]},    cell.repr(), '%s(len=O).r'%NAME)
    assertion(struct.pack('<I',0),     cell.pack(), '%s(len=0).p'%NAME)
    assertion(None,                    cell.check(),'%s(len=0).c'%NAME)
    cell = TYPE(len=2)
    assertion({'len':2,'array':[]},     cell.repr(), '%s(len=2).r'%NAME)
    assertion(struct.pack('<I',2),      cell.pack(), '%s(len=2).p'%NAME)
    assertion(None,                     cell.check(),'%s(len=2).c'%NAME)
    cell['array'].unrepr([0,7])
    assertion({'len':2,'array':[0,7]},  cell.repr(), '%s(l=2)[0,7].r'%NAME)
    assertion(struct.pack('<III',2,0,7),cell.pack(), '%s(l=2)[0,7].p'%NAME)
    assertion(rule_fail(cell),          cell.check(),'%s(l=2)[0,7].c'%NAME)
    cell = TYPE(len=8,array=[8,9])
    assertion({'len':8,'array':[8,9]},  cell.repr(), '%s(l=8,[8,9]).r'%NAME)
    assertion(struct.pack('<III',8,8,9),cell.pack(), '%s(l=8,[8,9]).p'%NAME)
    assertion(None,                     cell.check(),'%s(l=8,[8,9]).c'%NAME)
    cell = TYPE(array=[8,9])
    assertion({'len':8,'array':[8,9]},  cell.repr(), '%s(a=[8,9]).r'%NAME)
    assertion(struct.pack('<III',8,8,9),cell.pack(), '%s(a=[8,9]).p'%NAME)
    assertion(None,                     cell.check(),'%s(a=[8,9]).c'%NAME)
    cell = TYPE(len=7,array=[8,9])
    assertion({'len':7,'array':[8,9]},  cell.repr(), '%s(l=7,[8,9]).r'%NAME)
    assertion(struct.pack('<III',7,8,9),cell.pack(), '%s(l=7,[8,9]).p'%NAME)
    assertion(rule_fail(cell),          cell.check(),'%s(l=7,[8,9]).c'%NAME)
    data = struct.pack('<IIIIIII',8,0,1,2,3,4,5)
    cell = TYPE(data)
    assertion({'len':8,'array':[0,1]},      cell.repr(), '%s(data).r'%NAME)
    assertion(data[:12],                    cell.pack(), '%s(data).p'%NAME)
    assertion(None,                         cell.check(),'%s(data).c'%NAME)
    assertion([slice(12,28)], cell.not_parsed.ranges, '%s(data).x'%NAME)
    cell = TYPE()
    cell['array'].unrepr([0,5,0,0])
    assertion({'len':16,'array':[0,5,0,0]}, cell.repr(),'%s()[0,5,0,0]'%NAME)
    cell = TYPE()
    cell['array'].unrepr([0,5,0])
    assertion({'len':12,'array':[0,5,0]},   cell.repr(),'%s()[0,5,0]'%NAME)

def test_string_length_constraint(assertion):
    class SLX(Struct):
        _fields = [
            ('len',      Int),
            ('text',     VarStr),
            ]
        _rules = [
            RuleEqual('len', 'text.count'),
            ]
        _test_empty_repr = {'len':None,'text':''}
        _test_empty_pack = None
    class SL4(Struct):
        _fields = [
            ('len',      Int.default(4)),
            ('text',     VarStr),
            ]
        _rules = [
            RuleEqual('len', 'text.count'),
            ]
        _test_empty_repr = {'len':4,'text':''}
        _test_empty_pack = struct.pack('<I',4)
    rule_fail = lambda cell: "\n".join(["<%s"%NAME,
        "   'len' at 0x0: <%s value=7>"%cell['len'].__class__.__name__,
        "  'text' at 0x4: <VarStr wrapped=<Str[2]",
        "      0 at 0x4: <Char value='A'>",
        "      1 at 0x5: <Char value='B'>",
        "    >>",
        "> does not satisfy RuleEqual('len', 'text.count')"])
    for TYPE in (SLX, SL4):
        NAME = TYPE.__name__
        cell = TYPE()
        assertion(TYPE._test_empty_repr,   cell.repr(), '%s().r'%NAME)
        assertion(TYPE._test_empty_pack,   cell.pack(), '%s().p'%NAME)
        assertion(None,                    cell.check(),'%s().c'%NAME)
        cell = TYPE(len=0)
        assertion({'len':0,'text':''},     cell.repr(), '%s(len=O).r'%NAME)
        assertion(struct.pack('<I',0),     cell.pack(), '%s(len=0).p'%NAME)
        assertion(None,                    cell.check(),'%s(len=0).c'%NAME)
        cell = TYPE(len=2)
        assertion({'len':2,'text':''},      cell.repr(), '%s(len=2).r'%NAME)
        assertion(struct.pack('<I',2),      cell.pack(), '%s(len=2).p'%NAME)
        assertion(None,                     cell.check(),'%s(len=2).c'%NAME)
        assertion(cell['text']['count'], cell['text', 'count'], '%s.text.len'%NAME)
        data = struct.pack('<I6s',4,mkbytes('ABCDEF'))
        cell = TYPE(data)
        assertion({'len':4,'text':'ABCD'},  cell.repr(), '%s(data).r'%NAME)
        assertion(data[:8],                 cell.pack(), '%s(data).p'%NAME)
        assertion(None,                     cell.check(),'%s(data).c'%NAME)
        assertion([slice(8,10)], cell.not_parsed.ranges, '%s(data).x'%NAME)
        cell = TYPE(len=2,text='AB')
        assertion({'len':2,'text':'AB'},      cell.repr(),"%s(l=2,'AB').r"%NAME)
        assertion(struct.pack('<IBB',2,65,66),cell.pack(),"%s(l=2,'AB').p"%NAME)
        assertion(None,                      cell.check(),"%s(l=2,'AB').c"%NAME)
        cell = TYPE(text='AB')
        assertion({'len':2,'text':'AB'},      cell.repr(), "%s(a='AB').r"%NAME)
        assertion(struct.pack('<IBB',2,65,66),cell.pack(), "%s(a='AB').p"%NAME)
        assertion(None,                       cell.check(),"%s(a='AB').c"%NAME)
        cell = TYPE(len=7,text='AB')
        assertion({'len':7,'text':'AB'},      cell.repr(),"%s(l=7,'AB').r"%NAME)
        assertion(struct.pack('<IBB',7,65,66),cell.pack(),"%s(l=7,'AB').p"%NAME)
        assertion(rule_fail(cell),           cell.check(),"%s(l=7,'AB').c"%NAME)

def test_invalid_unpack(assertion):
    """ unpack with too short bytestring. """
    tst = "Int('')"
    msg = "Unpack 'Int' with not enough data"
    try:
        Int(struct.pack(""))
        assertion(0,1, "%s should have raised a ValueError"%tst)
    except ValueError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = "Str[2]('')"
    msg = "Unpack 'Char' with not enough data"
    try:
        Str[2](struct.pack(""))
        assertion(0,1, "%s should have raised a ValueError"%tst)
    except ValueError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    TYPE = Struct[[('a', Bits[4]), ('b', Bits[4])]]
    NAME = TYPE.__name__
    tst = "%s('')"%NAME
    msg = "Unpack 'Bits[4]' with not enough data"
    try:
        TYPE(struct.pack(""))
        assertion(0,1, "%s should have raised a ValueError"%tst)
    except ValueError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_string_fixedvalue(assertion):
    """ Cell value fixed to a given value. """
    TYPE = Str[4].fixed('TEST')
    NAME = TYPE.__name__
    cell = TYPE()
    data = mkbytes('TEST')
    assertion(data, cell.pack(), '%s()'%NAME)
    cell.unrepr('TEST')
    assertion(data, cell.pack(), '%s.unrepr(TEST)'%NAME)
    tst = "%s.unrepr(...) invalid value"%NAME
    msg = "Char.fixed('T') fixed at 84, cannot be set at 88"
    try:
        cell.unrepr('XXXX')
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = "%s.unpack(...) invalid value"%NAME
    msg = "Char.fixed('T') fixed at 84, cannot be set at 88"
    try:
        cell.unpack(mkbytes('XXXX'))
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = "%s(...) invalid value"%NAME
    msg = "Char.fixed('T') fixed at 84, cannot be set at 88"
    try:
        cell = TYPE(mkbytes('XXXX'))
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_struct_fixedvalue(assertion):
    """ Subcell value fixed to a given value. """
    class StructFixed(Struct):
        _fields = [
            ('a', Str[4].fixed('TEST')),
            ('b', Int.default(0)),
            ]
    TYPE = StructFixed
    NAME = TYPE.__name__
    cell = TYPE()
    cell.unrepr({'a':'TEST'})
    data = cell.pack()
    assertion(mkbytes('TEST\0\0\0\0'), data, '%s.unrepr(ok)'%NAME)
    tst = "%s.unrepr(...) invalid value"%NAME
    msg = "Char.fixed('T') fixed at 84, cannot be set at 89"
    try:
        cell.unrepr({'a':'YYYY'})
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = "%s.unpack(...) invalid value"%NAME
    msg = "Char.fixed('T') fixed at 84, cannot be set at 90"
    try:
        cell.unpack(mkbytes('ZZZZ\0\0\0\0'))
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = "%s(a=...) invalid value"%NAME
    msg = "Char.fixed('T') fixed at 84, cannot be set at 71"
    try:
        cell = cell.__class__(a='GLOP')
        assertion(0,1, "%s should have raised a CellError"%tst)
    except CellError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_string_length_constraint_insubcell(assertion):
    class HeaderAndText(Struct):
        _fields = [
            ('hdr', Struct[[('len',Int.default(4)),
                            ('int',Int)]]),
            ('text', VarStr),
            ]
        _rules = [
            RuleEqual('hdr.len', 'text.count'),
            ]
    TYPE = HeaderAndText
    NAME = TYPE.__name__
    cell = TYPE()
    assertion(None, cell.pack(), "%s() with default"%NAME)
    data = mkbytes('\x02\0\0\0\x0a\0\0\0ABCD')
    cell = TYPE(data)
    assertion(2, cell['hdr']['len'].work(), "Subsubcell 'hdr.len'")
    assertion(2, cell['text']['count'].work(), "Subsubcell 'text.count'")
    assertion('AB', cell['text'].repr(), "Subcell 'text'")
    assertion([slice(10, 12)],
        cell.not_parsed.ranges,
        "%s(data) not everything parsed"%NAME)
    assertion(data[:10], cell.pack(), "%s(data) with padding"%NAME)
    assertion(data, cell.pack(with_holes=True),'%s(data).pack(with_holes)'%NAME)
    tst = "%s.unpack with not enough data"%NAME
    msg = "VarStr unpack wrong count 10 != 5"
    try:
        data = mkbytes('\x0a\0\0\0\x02\0\0\0ABCDE')
        cell = TYPE(data)
        assertion(0,1, "%s should have raised a ValueError"%tst)
    except ValueError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)
    tst = "%s.unpack with very large size"%NAME
    msg = "VarStr unpack wrong count 1481852244 != 5"
    try:
        data = mkbytes('TESX\x02\0\0\0ABCDE')
        cell = TYPE(data)
        assertion(0,1, "%s should have raised a ValueError"%tst)
    except ValueError:
        e = sys.exc_info()[1]
        assertion(msg, str(e), tst)

def test_rules_insubcell(assertion):
    class SubCell(Struct):
        _fields = [
            ('a', Int),
            ('b', Int),
            ]
        _rules = [
            RuleEqual('a', 'b'),
            ]
    class WithSubCell(Struct):
        _fields = [ ('x', SubCell) ]
    TYPE = WithSubCell
    NAME = TYPE.__name__
    cell = TYPE()
    assertion({'x': {'a': None, 'b': None}}, cell.work(), '%s()'%NAME)
    cell['x','b'].unwork(2)
    assertion({'x': {'a': 2,    'b': 2   }}, cell.work(), '%s()'%NAME)


def run_test(assertion):
    #test_search_trees(assertion)
    #test_binary_representation(assertion)
    #test_struct_constraintdefault(assertion)
    #test_two_constraints(assertion)
    #test_string_length_constraint(assertion)
    #test_string_length_constraint_insubcell(assertion)
    #test_endianess_ptrsize(assertion)
    #test_at_offset(assertion)
    #test_array_fixed_length(assertion)
    #test_array_variable_length(assertion)
    #display_len_constraint(assertion)
    #test_simple_cells(assertion)
    #test_struct_attributes_elfesteem(assertion)
    #test_struct_equal(assertion)
    #test_array_variable_length(assertion)
    #test_array_length_constraint(assertion)
    #test_array_struct(assertion)
    #test_struct_equal_pairs(assertion)
    #test_rules_insubcell(assertion)
    #test_array(assertion)
    #test_string(assertion)
    #test_array_packlen_constraint(assertion)
    #print("WAS SELECTION OF TESTS");return
    for name, value in dict(globals()).items():
        if name.startswith('test_'):
            value(assertion)

if __name__ == "__main__":
    run_tests(run_test)
