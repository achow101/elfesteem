# Framework for the manipulation of binary content.
# Many concepts taken from https://bitbucket.org/secdev/scapy3-prototype2/
# Aims at compatibility with traditional elfesteem and with scapy2.

"""
    Each object is represented in a tree of cells. There are three types
    of cells: Leaf, Node or Wrap.
    
    Leaf: these cells have their own content, stored in the private member
    cell._content. The standard Leaf classes are:
    - Data: raw binary data
    - Bits, Byte, Short, Int, Quad: integer types
    - Ptr: integer with size depending on the 'ptrsize' in the tree of cells
    - [TODO] floating point
    / StrFixLen
    / StrVarLen
    
    Node: these cells contain subcells, stored in the private member
    cell._subcells. The number and type of subcells are known when
    the cell is created. The standard Node classes are:
    - Struct: subcells are contiguous in the binary representation
    - Collection: subcells are at given offsets in the binary repr.
    - ArrayFixLen: length of array is externally defined
    / ArrayVarLen: length of array is internally defined
    
    Wrap: these cells contain only one subcell, of variable type,
    stored in the private member cell._wrapped. This third type of
    cells is the only way to have the type of a subcell depending
    on some parameter.
    [TODO: better description]
    Union: when a cell type is defined as Union, then all its subclasses
    are variants of this cell type. When a cell of this type is created,
    one of this variants is used, the first valid one in the order of
    creation of the subcell types. NB: valid means that no ValueError
    is raised.
    
    Array subcells and Str characters are accessed with the syntax cell[i]
    with an integer i (negative i meaning starting from the end) and the
    length of Array and Str can be read (and written for FixLen variants)
    with cell['len'] (virtual subcell of name 'len').
    Struct and Collection subcells are accessed with the syntax cell[id]
    where id is a string used as a unique identifier of the subcell. Some
    optionals API (to mimic scapy2 or elfesteem) can be added to allow subcell
    access with the syntax cell.id (which is less versatile, because many
    values of id are forbidden, e.g. the one containing dots or spaces,
    and also 'class' for example).
    
    Each cell can be:
    - defined: its content (own content and/or subcells) has been explicitely
      written (by undata, unpack, unwork or unrepr, cf. below)
    - undefined: its content has not been defined. In that case, when the
      cell is read, the result may be a default value or a computed value
      (the difference being that default values don't depend on anything
      else in the tree of cells, while computed values can use other values)
    [TODO: check that this is valid for all cell types below]
    
    The content of a cell can be manipulated through various views:
    - work()/unwork(): a working representation that can be manipulated as
      standard python types, e.g. integers, strings, lists. This is obtained
      as a recursive call, with automatic computation of undefined cells.
      This can be seen as a de-serialization of the cell and its subcells.
    - repr()/unrepr(): usually same as the 'work' representation, but for
      some cell types it is a different human-readable representation, e.g.
      IP addresses being '127.0.0.1' instead of 2130706433.
    - pack()/unpack()/unpack_from(): binary representation, which in python3
      is of type bytes and in python2 is of type str. This representation
      can be seen as an extension of the native python struct module. More
      details below.
    - packlen(): fast computation of len(pack())
    - binrepr(): backend for pack(), which takes into account the fact that
      there may be overlapping or missing chunks in the binary representation
      of the cell.
    - show(): a visual representation of the content of the cell, with a
      multi-line layout. There is no unshow() because this representation
      is not meant to be parsed.
    - path(): the root of the tree, and the path to the current cell.
    - isdef(): test telling if the value of the cell has been defined.
    - init_empty(): not meant to be called directly.
    
    The creation of a cell object is made by one of these methods:
    - cell = Cell()
      creation of a new object with undefined content.
    - cell = Cell(bytestr)
      creation of a new object by parsing the bytestring; it is almost the
      same as cell = Cell().unpack(bytestr), but if a part of the bytestring
      it not used, it is stored and can be recovered by pack(with_holes=True).
    - cell = Cell(field=value,...)
      creation of a new object by specifying the value of some fields.
      Same result as cell.unrepr({'field':value,...})
    
    Rules aka. Constraints
    When calling work() (or show/pack/binrepr/repr, which are all based
    on work) either the cell value has been defined (by unwork/unpack/...)
    and therefore this value is returned, or it has not been defined and
    its value is computed.
    
    Bindings: for scapy bind_layers / unions
    
    Default/Fixed: [TODO]
    in some cases, Leaf cells are fixed to a specific value (typically
    a magic number or an identifier) and a ValueError exception is raised
    if one tries to put another value. This property can be used when
    parsing Union where a simple selector is not available.
    
----
    
    - cell.unpack(bytestr, offset=off)
      Modification of the cell by parsing the bytestring, with the optional
      parameter offset; returns self.
      If bytestr does not satisfy the constraints, a ConstraintError is
      raised.
    - bytestr = cell.pack()
      Creation of the bytestring corresponding to the content of the cell,
      or None if it is not possible.
      Note that cell.packlen() == len(cell.pack()) without computing
      cell.pack(); this is useful to avoid some infinite recursions.
    
    For some cell types, the binary representation cannot be a bytestring.
    This is the case when the packing method puts subcells at specific
    offsets in the final bytestring: parts of the final bytestream may be
    unspecified (sparse) or may be incoherent (overlapping). Therefore
    pack() is build on binrepr() which generates a BinRepr.
    
    A cell type can be specialized with arguments between brackets. For
    example numeric types can have a default value different from 0, e.g.
    Int[2] is a type for 4-bytes integers, with default value at 2.
    
    Constraints:
    A cell can be equipped with constraints.
    [TODO: describe; detect loops]
"""

import struct, sys
from elfesteem.core.binrepr import BinRepr

import logging
log = logging.getLogger("cell")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.ERROR)

# unpack_from appeared in python 2.5; we emulate it for older python, we want
# to use it in recent python, because it is more efficient than unpack.
if not hasattr(struct, 'unpack_from'):
    struct.unpack_from = lambda fmt, buffer, offset=0: struct.unpack(fmt, buffer[offset:offset+struct.calcsize(fmt)])

##########################################################################
# CELLS
# Main definitions, inherited by everyone.

class CellError(ValueError):
    """ Error when trying to create / modify a cell. """

class CellMetaclass(type):
    """ To be able to create specialized classes, e.g. Array[Int]. """
    def __new__(meta, name, bases, dct):
        for b in bases:
            if hasattr(b, '_update_dct'):
                b._update_dct(name, dct)
        cls = type.__new__(meta, name, bases, dct)
        if hasattr(cls, '_check_definition'): cls._check_definition()
        return cls
    def __getitem__(cls, value):
        new_name, new_dict = cls._cls_getitem(value)
        return cls.__class__.__new__(cls.__class__, new_name, (cls,), new_dict)
    def default(cls, value):
        new_name, new_dict = cls._cls_default(value)
        return cls.__class__.__new__(cls.__class__, new_name, (cls,), new_dict)
    def fixed(cls, value):
        new_name, new_dict = cls._cls_fixed(value)
        return cls.__class__.__new__(cls.__class__, new_name, (cls,), new_dict)
CellBase = CellMetaclass('CellBase', (object,), {})

class Cell(CellBase):
    def __init__(self, *args, **kargs):
        """ Declaration of a type: object with default content. """
        self._parent = kargs.pop('_parent', None)
        self._name = kargs.pop('_name', None)
        self._rule_manager = None
        for a_name, a_type in self._virtual_attributes:
            setattr(self, '_'+a_name, a_type(_parent=self,_name=a_name))
        if len(args) == 0 and len(kargs) == 0:
            self.init_empty()
        elif len(args) == 0 and kargs:
            self.unrepr(kargs)
        elif len(args) == 1 and len(kargs) == 0:
            data, = args
            if hasattr(data, 'pack'):
                # Compatibility with elfesteem's StrPatchwork
                data = data.pack()
            from elfesteem import intervals
            self.filesize = len(data)
            self.not_parsed = intervals.Intervals().add(0,self.filesize)
            self.not_parsed.data = BinRepr()
            self.unpack(data, not_parsed=self.not_parsed)
            for i in self.not_parsed.ranges:
                self.not_parsed.data[i.start] = data[i.start:i.stop]
            l = len(self.not_parsed.data)
            if l:
                log.warning("Part of the bytestring is not parsed: %d bytes", l)
        else:
            raise CellParsingError("%s has invalid args %s %s"
                % (self.__class__,args,kargs))
    def pack(self, **kargs):
        """ Returns the bytestring representing this object,
            or None if it cannot be converted to a bytestring. """
        try:
            r = self.binrepr()
        except TypeError:
            return None
        if r is None:
            return None
        if kargs.pop('with_holes', False):
            r[0] = self.not_parsed.data
        return r.pack(**kargs)
    def repr(self):
        """ Returns the pretty representation. """
        return self.work2repr(self.work())
    def unrepr(self, *args, **kargs):
        """ Create content from pretty representation. """
        if   len(args) == 0 and len(kargs) == 0:
            value = None
        elif len(args) == 1 and len(kargs) == 0:
            value = args[0]
        elif len(args) == 0 and len(kargs) > 0:
            value = kargs
        else: TODO
        if hasattr(self, '_unwork_unrepr'): self._unwork_unrepr(value, 'unrepr')
        else:                               self.unwork(self.repr2work(value))
        return self
    def check(self):
        """ Checks that all rules are valid. """
        for rule in getattr(self, '_rules', ()):
            ret = rule.check(self)
            if ret is not None:
                return ret
    def path(self):
        p = []
        while getattr(self, '_parent', None) is not None:
            if self._name is not None: p.insert(0, self._name)
            self = self._parent
        return (self, p)
    def _get_attr_ancestor(self, name, default=None):
        while hasattr(self, '_parent'):
            if hasattr(self, name):
                return getattr(self, name)
            self = self._parent
        return default
    def _global_pos(self):
        # Position in the packed bytestring; used for show()
        pos = 0
        head = self
        while head is not None:
            if hasattr(head._parent, '_pos'):
                pos += head._parent._pos.get(head._name, 0)
            head = head._parent
        return pos
    _virtual_attributes = []
    isvalid = lambda self: self.isdef()

##########################################################################
# LEAFS
# Various type of cells that don't have subcells.

class Leaf(Cell):
    _content = None
    _default = None
    def _cls_getitem(cls, value):
        if not hasattr(value, 'values'):
            raise CellError('%s cannot be specialized with enum %r'
                % (cls.__name__, value))
        new_name = cls.__name__ + '[enum]'
        new_dict = { '_enum': value }
        return new_name, new_dict
    _cls_getitem = classmethod(_cls_getitem)
    def _cls_default(cls, value):
        new_name = cls.__name__ + '.default(%r)'%value
        value = cls.repr2work(value)
        new_dict = { '_default': value }
        return new_name, new_dict
    _cls_default = classmethod(_cls_default)
    def _cls_fixed(cls, value):
        new_name = cls.__name__ + '.fixed(%r)'%value
        value = cls.repr2work(value)
        def check(self):
            if self._content != value:
                raise CellError('%s fixed at %r, cannot be set at %s'
                    % (self.__class__.__name__, value, self.work()))
        new_dict = { '_default': value, '_check_fixed': check }
        return new_name, new_dict
    _cls_fixed = classmethod(_cls_fixed)
    isdef = lambda self: self._content is not None
    def init_empty(self):
        pass
    def work(self):
        # For a Leaf, the working representation is its content (if
        # defined. If not, then the rule manager tries to generate
        # a value, and returns self._default if it fails.
        # The rule manager is created in a semi-persistent way: the
        # goal is to enforce the rules only once, when work() is
        # recursively called in a subtree.
        if self.isdef():
            return self._content
        head, path = self.path()
        if head._rule_manager is not None:
            return head._rule_manager.get(path, default=self._default)
        else:
            head._rule_manager = RuleManager()
            head._rule_manager.create(head)
            val = head._rule_manager.get(path, default=self._default)
            head._rule_manager = None
            return val

class Numeric(Leaf):
    def unwork(self, value):
        if value is None:
            self._content = None
            return self
        value + 0 # check input type is numeric
        self._content = value
        if hasattr(self, '_check_fixed'): self._check_fixed()
        return self
    def unpack(self, value, offset=0, **kargs):
        value + struct.pack('') # check input type is bytestring
        try:
            self._content, = struct.unpack_from(self._sex+self._fmt,
                                                value, offset=offset)
        except struct.error:
            self._content = None
        if self._content is None:
            raise CellError("Unpack %r with not enough data"
                % self.__class__.__name__)
        if hasattr(self, '_check_fixed'): self._check_fixed()
        if 'not_parsed' in kargs:
            kargs['not_parsed'].delete(offset,offset+self.packlen())
        return self
    def binrepr(self):
        val = self.work()
        if val is not None:
            val = struct.pack(self._sex+self._fmt, val)
        return BinRepr(val)
    def show(self):
        return "<%s value=%s>" % (self.__class__.__name__, self.repr())
    def repr2work(cls, val):
        if val in getattr(cls, '_enum', {}).keys():
            val = cls._enum[val]
        return val
    repr2work = classmethod(repr2work)
    def work2repr(self, val):
        enum = getattr(self, '_enum', {})
        if hasattr(enum, 'name'):
            val = enum.name[val]
        elif val in enum.values():
            val = [ k for k, v in self._enum.items() if v == val ][0]
        return val
    packlen = lambda self: struct.calcsize(self._fmt)
    _sex = property(lambda _: _._get_attr_ancestor('_endianess', default='='))
    __int__ = lambda self: self.work()
class Byte(Numeric):
    _fmt = 'B'
    packlen = lambda self: 1
class Short(Numeric):
    _fmt = 'H'
    packlen = lambda self: 2
class Int(Numeric):
    _fmt = 'I'
    packlen = lambda self: 4
class Quad(Numeric):
    _fmt = 'Q'
    packlen = lambda self: 8

class Char(Byte):
    def show(self):
        return "<%s value=%r>" % (self.__class__.__name__, self.repr())
    def repr2work(cls, val):
        if val is not None: val = ord(val)
        return val
    repr2work = classmethod(repr2work)
    def work2repr(self, val):
        if val is not None: val = chr(val)
        return val

class Ptr(Numeric):
    _fmt = property(lambda self:
                {32: 'I', 64: 'Q'}
                [self._get_attr_ancestor('_ptrsize', default=None)])
    def show(self):
        """ Pointers are shown in hexa and with leading zeroes. """
        if getattr(self, '_content', None) is None:
            return "<%s value=%s>" % (self.__class__.__name__, None)
        else:
            return "<%s value=0x%0*x>" % (self.__class__.__name__,
                self._get_attr_ancestor('_ptrsize', default=None) // 4,
                self.work())

class Bits(Numeric):
    """ Contains some bits; designed to be part of a Struct. """
    def _cls_getitem(cls, value):
        """ Specifies the length in bits, and then the default value. """
        if hasattr(cls, '_bitlen'):
            return Numeric._cls_getitem(value)
        bitlen = value
        bytelen = (bitlen+7)//8
        new_name = cls.__name__ + '[%r]'%value
        new_dict = { '_bitlen': bitlen, '_bytelen': bytelen }
        return new_name, new_dict
    _cls_getitem = classmethod(_cls_getitem)
    def unpack(self, data, offset=0, **kargs):
        bitoffset = int((offset-int(offset))*8)
        offset = int(offset)
        sex = self._sex
        assert self._bitlen + bitoffset <= 8*self._bytelen
        try:
            val = struct.unpack_from("B"*self._bytelen, data, offset=offset)
        except struct.error:
            val = None
        if val is None:
            raise CellError("Unpack %r with not enough data"
                % self.__class__.__name__)
        if   sex == '<':
            self._content = 0
            for i, v in enumerate(val):
                self._content += v << (i*8)
            self._content >>= bitoffset
            self._content &= (1<<self._bitlen)-1
        elif sex == '>':
            self._content = 0
            for v in val:
                self._content <<= 8
                self._content += v
            self._content >>= (8*self._bytelen-bitoffset-self._bitlen)
            self._content &= (1<<self._bitlen)-1
        else:
            ERROR_UNKNOWN_ENDIANESS
        if hasattr(self, '_check_fixed'): self._check_fixed()
        if 'not_parsed' in kargs:
            kargs['not_parsed'].delete(offset,offset+self._bytelen)
    def binrepr(self, bitoffset=0):
        sex = self._sex
        val = self.work()
        if   sex == '<':
            val <<= bitoffset
            val = [(val>>(8*i))&0xff for i in range(self._bytelen)]
        elif sex == '>':
            val <<= ((-self._bitlen-bitoffset)&0x7)
            val = [(val>>(8*i))&0xff for i in range(self._bytelen-1,-1,-1)]
        else:
            ERROR_UNKNOWN_ENDIANESS
        return BinRepr(struct.pack("B"*self._bytelen, *val))
    packlen = lambda self: float(self._bitlen) / 8
    def __len__(self):
        """ The semantics being the length in bytes, we don't want to
            rely on non-obvious assumptions: 'bitlen' is the exact length
            in bits, and 'bytelen' the length in octets, rounded up.
        """
        return None

class NamedConstants(object):
    """ Definition for named constants, e.g. for enum in Leaf """
    def __init__(self, data, glob=None):
        self.text = {}
        self.name = {}
        self.dict = {}
        self.glob = glob
        for x in data:
            self.extend(*x)
    def extend(self, value, name, text=True):
        # - value is a numeric value
        # - name is the official name for this value
        #   if a value appears many times, the last name is preferred
        # - text is optional, and is a description of this value,
        #   when used as an enum; if text is not defined, name is used;
        #   if text is None, then it is not in the enum
        self.dict[name] = value
        self.name[value] = name
        if text is True: text = name
        if text is not None: self.text[value] = text
        if self.glob is not None:
            self.glob[name] = value
    def __getitem__(self, item):
        return self.dict[item]
    def keys(self):
        return self.dict.keys()
    def values(self):
        return self.dict.values()
    def items(self):
        return self.dict.items()

class VirtualAttribute(Numeric):
    """ A virtual attribute changes the behaviour of unwork/unpack/... """
    def unwork(self, value):
        # We don't allow to change the length of an existing non-empty
        # object, because the semantics would be unclear: should we
        # truncate/extend it or do nothing?
        if value is not None and self._parent.isvalid():
            previous = self._attribute()
            if previous != 0:
                raise CellError('%s %s is %r, cannot be set at %s'
                    % (self._parent.__class__.__name__,
                       self._attr_name, previous, value))
        return Numeric.unwork(self, value)
    def work(self):
        if self._parent.isvalid():
            value = self._attribute()
            if value != 0:
                return value
        return Numeric.work(self)
    def isdef(self):
        # Ncessary for RuleManager
        # _content may be None when it should not,
        # i.e. when self._attribute is not None
        if self._content is not None: return True
        if self._parent.isvalid() and self._attribute() != 0: return True
        return False

class VirtualAttributePacklen(VirtualAttribute):
    _attr_name = 'bytelength'
    _attribute = lambda self: self._parent.packlen()

class Data(Leaf):
    """ Raw binary data """
    _maxsize = None
    _virtual_attributes = [ ('packlen', VirtualAttributePacklen) ]
    def init_empty(self):
        self._content = None
    def unwork(self, value):
        if value is None:
            self.init_empty()
            return self
        value + struct.pack('') # check input type is bytestring
        self._content = value
        if hasattr(self, '_check_fixed'): self._check_fixed()
        return self
    def unpack(self, value, offset=0, **kargs):
        value + struct.pack('') # check input type is bytestring
        if 'size' in kargs:
            end = offset + kargs['size']
        else:
            size = self._packlen.work()
            if size is None: end = len(value)
            else:            end = offset + size
        self._content = value[offset:end]
        if hasattr(self, '_check_fixed'): self._check_fixed()
        if 'not_parsed' in kargs:
            kargs['not_parsed'].delete(offset,end)
        return self
    def binrepr(self):
        return BinRepr(self.work())
    def show(self):
        return "<%s value=%r>" % (self.__class__.__name__, self.repr())
    repr2work = classmethod(lambda cls, val: val)
    work2repr = lambda self, val: val
    packlen = lambda self: len(self.work())
    def __getitem__(self, item):
        if item == 'packlen': return self._packlen
        return self._content.__getitem__(item)
    def __setitem__(self, item, value):
        if isinstance(item, slice): start, stop = item.start, item.stop
        else:                       start, stop = item, item+1
        assert stop - start == len(value)
        self._content = self._content[:start] + value + self._content[stop:]

##########################################################################
# NODES
# Various type of cells that have subcells of known count and type.

class Node(Cell):
    """ A Cell having subcells, the names and types of subcells being
        known when the cell is created.
        
        cls._layout: definition of the layout of subcell; a list of triples
            (k, t, p) where 'k' is the name of the subcell, 't' its type
            and 'p' a function that compute its position in the binary
            representation.
        cell._subcells: the values of the subcells of 'cell'
        cell._pos: a temporary storage for the positions of the subcells
            relative to the position of the cell
    """
    def _check_definition(cls):
        if not hasattr(cls, '_layout'): return
        keys = {}
        for k, x in cls._layout:
            if k in keys:
                raise CellError("Duplicate field %r"%k)
            if not isinstance(x, tuple):
                raise CellError("Field %r should be defined with a tuple"%k)
            t, v = x
            keys[k] = True
    _check_definition = classmethod(_check_definition)
    def _cls_default(cls, value):
        new_name = cls.__name__ + '.default(%r)'%value
        return new_name, { '_default': value }
    _cls_default = classmethod(_cls_default)
    def _cls_fixed(cls, value):
        new_name = cls.__name__ + '.fixed(%r)'%value
        return new_name, { '_fixed': value }
    _cls_fixed = classmethod(_cls_fixed)
    def _iter_name(cls):
        for k, (t, p) in cls._layout:
            yield k
    _iter_name = classmethod(_iter_name)
    def _type_specialize(cls, k, t):
        if hasattr(cls, '_fixed'):     return t.fixed  (cls._fixed  [k])
        elif hasattr(cls, '_default'): return t.default(cls._default[k])
        else:                          return t
    _type_specialize = classmethod(_type_specialize)
    def _iter_type(cls):
        for k, (t, p) in cls._layout:
            yield k, cls._type_specialize(k, t)
    _iter_type = classmethod(_iter_type)
    def _iter_pos(self):
        for k, (t, p) in self._layout:
            pos = p(self, k)
            self._pos[k] = pos
            yield k, self._type_specialize(k, t), pos
    isdef = lambda _: True
    unwork = lambda self, value: self._unwork_unrepr(value, 'unwork')
    # Content creation
    def init_empty(self):
        self._pos = {}
        self._subcells = {}
        for k, t in self._iter_type():
            self._subcells[k] = t(_parent=self,_name=k)
    def _unwork_unrepr(self, value, wrapped_function):
        log.debug("%s.%s(%r)",self.__class__.__name__,wrapped_function,value)
        if value is None:
            self.init_empty()
            return self
        if not hasattr(value, 'keys'):
            raise CellError("%s: cannot unwork %s"%(self.__class__.__name__,value.__class__.__name__))
        value = dict(value)
        self._pos = {}
        self._subcells = {}
        for k, t in self._iter_type():
            self._subcells[k] = t(_parent=self,_name=k)
            getattr(self._subcells[k], wrapped_function)(value.pop(k, None))
        if len(value):
            raise KeyError("Keys %r not in %s"%(list(value.keys()), self.__class__.__name__))
        return self
    def unpack(self, value, offset=0, **kargs):
        self._pos = {}
        self._subcells = {}
        for k, t, pos in self._iter_pos():
            self._subcells[k] = t(_parent=self,_name=k)
            if int(pos) == pos:
                pos = int(pos)
            self._subcells[k].unpack(value, offset=offset+pos, **kargs)
        return self
    # Reading the content
    def work(self):
        if self._subcells == {}:
            for k, t in self._iter_type():
                self._subcells[k] = t(_parent=self,_name=k)
        # For a Node, the working representation is the dictionary of
        # working representations of its subcells.
        return dict([(k,self._subcells[k].work()) for k in self._iter_name()])
    def binrepr(self):
        if self._subcells == {}:
            for k, t in self._iter_type():
                self._subcells[k] = t(_parent=self,_name=k)
        res = BinRepr()
        for k, t, pos in self._iter_pos():
            if k in self._subcells: cell = self._subcells[k]
            else:                   cell = t(_parent=self,_name=k)
            if int(pos) != pos:
                # Non-integer means that we are at bit level
                bitoffset = int((pos-int(pos))*8)
                val = cell.binrepr(bitoffset=bitoffset)
                res.xor(val, offset=int(pos))
            else:
                pos = int(pos)
                res[pos] = cell.binrepr()
        return res
    def show(self):
        if self._subcells == {}:
            for k, t in self._iter_type():
                self._subcells[k] = t(_parent=self,_name=k)
        depth = 0
        obj = self
        while getattr(obj, '_parent', None) is not None:
            depth += 1
            obj = obj._parent
        w = 0
        for k in self._iter_name():
            if len(repr(k)) > w: w = len(repr(k))
        for k in getattr(self, '_virtual_fields', []):
            if len(repr(k)) > w: w = len(repr(k))
        offset = self._global_pos()
        res = ["<%s" % self.__class__.__name__]
        for k, t, pos in self._iter_pos():
            params = (w, k, int(offset+pos), self._subcells[k].show())
            res.append("  %*r at %#x: %s" % params)
        for k in getattr(self, '_virtual_fields', []):
            params = (w, k, self[k].show())
            res.append("  %*r: %s" % params)
        res.append(">")
        return ("\n"+"  "*depth).join(res)
    def work2repr(self, val):
        res = {}; val = dict(val)
        for k in self._iter_name():
            if k in val: res[k] = self[k].work2repr(val.pop(k))
        if len(val): raise KeyError(list(val.keys()))
        return res
    def packlen(self):
        if self._subcells == {}:
            for k, t in self._iter_type():
                self._subcells[k] = t(_parent=self,_name=k)
        end = 0
        for k, t, pos in self._iter_pos():
            l = pos + self._subcells[k].packlen()
            if end < l: end = l
        if int(end) == end: end = int(end)
        return end
    def __getitem__(self, item):
        if self._subcells == {}:
            for k, t in self._iter_type():
                self._subcells[k] = t(_parent=self,_name=k)
        if isinstance(item, list) or isinstance(item, tuple):
            if   len(item) == 1: return self[item[0]]
            elif len(item) == 2: return self[item[0]][item[1]]
            else:                return self[item[0]][item[1:]]
        return self._subcells[item]
    def __iter__(self):
        if self._subcells == {}:
            for k, t in self._iter_type():
                self._subcells[k] = t(_parent=self,_name=k)
        for k in self._iter_name():
            yield self._subcells[k]

class Struct(Node):
    def _check_definition(cls):
        if not hasattr(cls, '_fields'): return
        keys = {}
        for k, x in cls._fields:
            if k in keys:
                raise CellError("Duplicate field %r"%k)
            keys[k] = True
    _check_definition = classmethod(_check_definition)
    def _cls_getitem(cls, value):
        assert isinstance(value, list)
        new_name = "unnamed " + cls.__name__
        new_dict = { '_fields': value }
        return new_name, new_dict
    _cls_getitem = classmethod(_cls_getitem)
    def _iter_name(cls):
        for k, t in cls._fields:
            yield k
    _iter_name = classmethod(_iter_name)
    def _iter_type(cls):
        for k, t in cls._fields:
            yield k, cls._type_specialize(k, t)
    _iter_type = classmethod(_iter_type)
    def _iter_pos(self):
        if len(self._fields) == 0:
            return
        k, t = self._fields[0] 
        self._pos[k] = 0
        prv = k
        yield k, self._type_specialize(k, t), 0
        for k, t in self._fields[1:]:
            pos = self._pos[prv] + self._subcells[prv].packlen()
            self._pos[k] = pos
            prv = k
            yield k, self._type_specialize(k, t), pos

class Array(Node):
    """ Array is a variant of Struct, where all id are numeric.
        The number of elements is fixed when the array is defined, by the
        parameter _count. _iter_name and _iter_type are not classmethods
        because _count may depend on the instance, cf. VarArray.
    """
    def _check_definition(cls):
        if hasattr(cls, '_default') and len(cls._default) != cls._count:
            raise CellError("%s length should be %d, cannot be set at %d" %
                    (cls.__name__, cls._count, len(cls._default)))
        if hasattr(cls, '_fixed') and len(cls._fixed) != cls._count:
            raise CellError("%s length should be %d, cannot be set at %d" %
                    (cls.__name__, cls._count, len(cls._fixed)))
    _check_definition = classmethod(_check_definition)
    def _cls_getitem(cls, value):
        if not isinstance(value, tuple):
            _type, _count = value, 0
            new_name = cls.__name__ + '[%s]'%_type.__name__
        else:
            _type, _count = value
            new_name = cls.__name__ + '[%s,%s]'%(_type.__name__,_count)
        new_dict = { '_type': _type, '_count': _count}
        return new_name, new_dict
    _cls_getitem = classmethod(_cls_getitem)
    def _iter_name(self):
        for k in range(self._count):
            yield k
    def _iter_type(self):
        for k in range(self._count):
            yield k, self._type_specialize(k, self._type)
    def _iter_pos(self):
        if self._count == 0:
            return
        self._pos[0] = 0
        yield 0, self._type_specialize(0, self._type), 0
        for k in range(1, self._count):
            pos = self._pos[k-1] + self._subcells[k-1].packlen()
            self._pos[k] = pos
            yield k, self._type_specialize(k, self._type), pos
    def _unwork_unrepr(self, value, wrapped_function):
        if wrapped_function == 'unrepr' and value is not None:
            if len(value) != self._count:
                raise CellError("%s length should be %d, cannot be set at %d" %
                    (self.__class__.__name__, self._count, len(value)))
            value = dict([(i,value[i]) for i in range(len(value))])
        Node._unwork_unrepr(self, value, wrapped_function)
    def work2repr(self, val):
        return [self[i].work2repr(val[i]) for i in range(len(val))]
    def packlen(self):
        if self._subcells == {}:
            for k, t in self._iter_type():
                self._subcells[k] = t(_parent=self,_name=k)
        return sum([self._subcells[k].packlen() for k in self._iter_name()])

class Str(Array):
    """ Str is a special case of Array, where elements are bytes.
        The internal representation is not a python string, which allows
        easy modification of one byte only.
        Note that this Str type does not deal with encodings.
    """
    def _cls_getitem(cls, value):
        new_name = cls.__name__ + '[%r]'%value
        if isinstance(value, str):
            # Shortcut for Str[len(value)].default(value)
            new_dict = { '_count': len(value), '_default': value }
        else:
            new_dict = { '_count': value }
        return new_name, new_dict
    _cls_getitem = classmethod(_cls_getitem)
    _type = Char
    _count = 0
    def work2repr(self, val):
        s = ''
        for i in range(len(val)):
            s += chr(val[i])
        return s
    packlen = lambda self: self._count
    __str__ = lambda self: self.repr()

##########################################################################
# WRAPS

class Wrap(Cell):
    # Wrap: these cells contain only one subcell, of variable type,
    # stored in the private member cell._wrapped. The Wrap cells are
    # the only way to have the type of a subcell depending on some
    # parameter.
    work    = lambda self: self._wrapped.work()
    binrepr = lambda self: self._wrapped.binrepr()
    packlen = lambda self: self._wrapped.packlen()
    isdef   = lambda self: self._wrapped.isdef()
    __getitem__ = lambda self, item: self._wrapped[item]
    __iter__    = lambda self: iter(self._wrapped)
    unwork = lambda self, value: self._unwork_unrepr(value, 'unwork')

class Union(Wrap):
    _fallback = Data # Type used by default
    def init_empty(self):
        self._wrapped = self._fallback(_parent=self)
    def _unwork_unrepr(self, value, wrapped_function):
        if value is None:
            self.init_empty()
            return self
        if value.__class__ in self._options:
            value._parent = self
            self._wrapped = value
            return self
        for t in self._options + [ self._fallback ]:
            try:
                self._wrapped = t(_parent=self)
                getattr(self._wrapped, wrapped_function)(value)
                return self
            except CellError:
                pass
        raise CellError("%s: cannot unwork %s"%(self.__class__.__name__,value.__class__.__name__))
    def unpack(self, value, **kargs):
        for t in self._options + [ self._fallback ]:
            try:
                self._wrapped = t(_parent=self)
                self._wrapped.unpack(value, **kargs)
                return self
            except CellError:
                pass
        raise CellError("%s: cannot unpack %s"%(self.__class__.__name__,value.__class__.__name__))
    def show(self):
        res = "<%s union %s " % (self.__class__.__name__,
                                 [_.__name__ for _ in self._options])
        if self.isdef(): return res + "wrapped=%s>" % self._wrapped.show()
        else:            return res + "undefined>"
    def work2repr(self, val):
        if val.__class__ in self._options: return val
        return self._wrapped.work2repr(val)

class VirtualAttributeCount(VirtualAttribute):
    _attr_name = 'length'
    _attribute = lambda self: len(self._parent._wrapped._subcells)

class VarArray(Wrap):
    """ VarArray is an array of variable length """
    def _cls_getitem(cls, value):
        new_name = cls.__name__ + '[%s]'%value.__name__
        new_dict = { '_type': value }
        return new_name, new_dict
    _cls_getitem = classmethod(_cls_getitem)
    _wrapped_type = lambda self, length: Array[self._type, length]
    _wrapped = None
    _virtual_attributes = [ ('packlen', VirtualAttributePacklen),
                            ('count',   VirtualAttributeCount) ]
    def state(self):
        """ Four possible states """
        if self._wrapped is None:
            return 'invalid'
        if isinstance(self._wrapped, Data):
            return 'invalid'
        if len(self._wrapped._subcells):
            return 'defined'
        length = self._count.work()
        if length is None:
            assert not self._count.isdef()
            return 'undefined'
        if self._count.isdef() and length == 0:
            return 'defined'
        return 'virtual'
    isdef = lambda self: self.state() == 'defined'
    isvalid = lambda self: self._wrapped is not None and not isinstance(self._wrapped, Data)
    def init_empty(self):
        self._count.unwork(None) # array length is not constrained
        self._wrapped = self._wrapped_type(0)(_parent=self,_name='wrapped')
    def _unwork_unrepr(self, value, wrapped_function):
        # Virtual attribute 'len' constrains the number of elements of the
        # array.
        if value is None:
            self.init_empty()
            return self
        self._wrapped = None
        count = len(value)
        if self._count.isdef():
            if count != self._count.work():
                raise CellError('%s length should be %r, cannot be set at %s'
                    % (self.__class__.__name__, self._count.work(), count))
        else:
            self._count.unwork(count)
        self._wrapped = self._wrapped_type(count)(_parent=self,_name='wrapped')
        getattr(self._wrapped, wrapped_function)(value)
        return self
    def unpack(self, value, offset=0, **kargs):
        # We parse the elements of the array in a greedy way, it will avoid
        # to allocate a very big array when virtual attribute 'len' is too
        # big.
        self._wrapped = None
        count = self._count.work()
        if 'size' in kargs: size = kargs['size']
        else:               size = self._packlen.work()
        if size is None: end = len(value)
        else:            end = offset + size
        start = offset
        kargs = dict(kargs); kargs.pop('size', None)
        wrap = self._wrapped_type(0)(_parent=self,_name='wrapped')
        self._wrapped = wrap
        while True:
            assert len(wrap._subcells) == wrap._count
            if count is not None and count <= len(wrap._subcells):
                break
            if end <= start:
                break
            cell = wrap._type(_parent=wrap,_name=wrap._count)
            cell.unpack(value, offset=start, **kargs)
            wrap._subcells[wrap._count] = cell
            wrap._count += 1
            start += cell.packlen()
        if count is not None and count != len(wrap._subcells):
            raise ValueError("%s unpack wrong count %s != %s" %
                (self.__class__.__name__, count, len(wrap._subcells)))
        if size is not None and start != end:
            # Could not unpack an array; return raw data and complain
            kargs['size'] = size
            self._wrapped = Data(_parent=self,_name='wrapped')
            self._wrapped.unpack(value, offset=offset, **kargs)
            raise ValueError("%s unpack wrong packlen %s != %s" %
                (self.__class__.__name__, start-offset, end-offset))
        return self
    def __getitem__(self, item):
        if isinstance(item, list) or isinstance(item, tuple):
            if   len(item) == 1: return self[item[0]]
            elif len(item) == 2: return self[item[0]][item[1]]
            else:                return self[item[0]][item[1:]]
        if item == 'count':   return self._count
        if item == 'packlen': return self._packlen
        if not isinstance(self._wrapped, Data):
            return self._wrapped[item]
        TODO
    def show(self):
        res = "<%s " % self.__class__.__name__
        if not isinstance(self._wrapped, Data):
            res += "wrapped=%s>" % self._wrapped.show()
            return res
        else:
            if self._wrapped.isdef():
                return res + '%s>' % self._wrapped.show()
            res += "undefined"
            count = self._count.work()
            if count is not None: res += " of length %d" % count
            size = self._packlen.work()
            if size is not None: res += " of size %d" % size
            return res + ">"
    def work2repr(self, val):
        if val is None: return None
        if isinstance(val, dict):
            return [self[i].work2repr(val[i]) for i in range(len(val))]
        # when unpack made self._wrapped of type Data
        return val

class VarStr(VarArray):
    """ VarStr is string of variable length """
    _wrapped_type = lambda self, length: Str[length]
    def work2repr(self, val):
        if val is None: return None
        return Str().work2repr(val)

##########################################################################
# RULES

from elfesteem.core.tree import set

class ComponentType(object):
    def __init__(self):
        self.type = None
    def addtype(self, rule):
        if rule.__class__ == RuleEqual:
            if self.type is None: self.type = 'constant'
            # else, it does not change the constraints on this component
        elif rule.__class__ == RuleLinear:
            if   self.type is None: self.type = 'linear'
            elif self.type is 'constant': self.type = 'linear'
        else:
            log.error("Unknown rule type %r" % rule.__class__.__name__)
class ConnectedComponents(object):
    """ Manages the connected components of subcells impacted by rules """
    def __init__(self):
        self.seen = {}
        self.comp = {}
    def add(self, basepath, rule):
        paths = [tuple(basepath+_) for _ in rule.paths]
        c = set()
        for p in paths:
            if p in self.seen:
                c.add(self.seen[p])
        if len(c) == 0:
            # New connected component
            t = ComponentType()
            self.comp[t] = []
            for p in paths:
                self.comp[t].append(p)
                self.seen[p] = t
        elif len(c) == 1:
            # Extend existing connected component
            t = c.pop()
            for p in paths:
                if not p in self.seen: self.comp[t].append(p)
                self.seen[p] = t
        else:
            # Merge existing connected components
            TODO
        t.addtype(rule)

class RuleManager(object):
    """ The RuleManager is created when work/repr/pack/show/... """
    def __init__(self):
        # '_computed' keys are the subcells that are impacted by the rules.
        # Its values are:
        # - first, True
        # - then, the type of the subcell
        # - finally, the value of the subcell
        self._computed = {}
        self._connected = ConnectedComponents()
    def create(self, head):
        # Enumerates the subcells impacted by the rules in the subtree
        # starting at 'head'
        self._parse_rules(head, [])
        # Aborts if no subcell impacted
        if not self._computed:
            return
        for k in self._computed.keys():
            self._computed[k] = head[k]
        for ctype, component in self._connected.comp.items():
            if   ctype.type == 'constant': self._enforce_constant(component)
            elif ctype.type == 'linear':   self._enforce_linear  (component)
            else: log.error("Unknown connected component type %s", ctype.type)
    def get(self, path, default=None):
        return self._computed.get(tuple(path), default)
    def _enforce_constant(self, component):
        r = []
        for k in component:
            c = self._computed[k]
            if c.isdef():
                v = c.work()
                if not v in r: r.append(v)
        if len(r) == 1:
            # Only one value appears, all subcells to be set to this value.
            for k in component:
                self._computed[k] = r[0]
        elif len(r) > 1:
            # More than one value appears: inconsistent content, undefined
            # subcells are set to their default value.
            for k in component:
                c = self._computed[k]
                if c._content is None: self._computed[k] = c._default
                else:                  self._computed[k] = c._content
        else:
            # No value appears: look at default values.
            r = []
            for k in component:
                c = self._computed[k]
                v = c._default
                if not v in r and v is not None: r.append(v)
            if len(r) == 1:
                # Only one value appears, all subcells to be set to this value.
                for k in component:
                    self._computed[k] = r[0]
            elif len(r) > 1:
                # More than one value appears: inconsistent default, undefined
                # subcells are set to their default value.
                for k in component:
                    self._computed[k] = self._computed[k]._default
            else:
                # No value appears.
                for k in component:
                    self._computed[k] = None
    def _enforce_linear(self, component):
        # [TODO] Generate the matrix that describes the relationships
        # between these subcells.
        # [TODO] Compute the kernel rank of the matrix. If negative then
        # it means that the rules are contradictory; else it is the number
        # of free values, which define all other values.
        log.error("Non implemented connected component type 'linear'")
    def _parse_rules(self, cell, path):
        if cell is None:
            pass
        elif isinstance(cell, Leaf):
            pass
        elif isinstance(cell, Node):
            for name in cell._subcells:
                self._parse_rules(cell._subcells[name], path+[name])
        elif isinstance(cell, Wrap):
            self._parse_rules(cell._wrapped, path)
        else:
            TODO
        for rule in getattr(cell, '_rules', ()):
            try:
                for target in rule.paths:
                    cell[target] # check that the path to target exists
                for target in rule.paths:
                    self._computed[tuple(path+target)] = True
                self._connected.add(path, rule)
            except KeyError:
                pass

class Rule(object):
    """ Base type, not to be used directly. """
    def apply_path(cls, cell, path):
        head = cell
        while head is not None:
            names = [_[0] for _ in getattr(head, '_fields', [])]
            if path[0] in names:
                break
            head = head._parent
        if head is None:
            raise KeyError("No %r in %r"%(path,cell.__class__.__name__))
        while head is not None and len(path):
            head = head[path[0]]
            path = path[1:]
        return head
    apply_path = classmethod(apply_path)
    def split_path(cls, path):
        if isinstance(path, str): return path.split('.')
        else:                     return path
    split_path = classmethod(split_path)

class RuleEqual(Rule):
    """ Arguments are paths to fields. """
    def __init__(self, *args):
        self.paths = [Rule.split_path(_) for _ in args]
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, ', '.join([repr('.'.join(_)) for _ in self.paths]))
    def check(self, cell):
        val = [ Rule.apply_path(cell, _).work() for _ in self.paths ]
        for v in val[1:]:
            if v != val[0]:
                return "%s does not satisfy %r" % (cell.show(), self)
        return None

class RuleLinear(Rule):
    """ Arguments are pairs (scalar, path to field). """
    def __init__(self, *args):
        self.paths = [Rule.split_path(p) for _, p in args]
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, ', '.join([repr('.'.join(_)) for _ in self.paths]))

##########################################################################
# EPILOGUE
# Compatibility layers.

class Attributes(object):
    """ Cell content can be accessed through attributes, e.g. cell.f """
    def __init__(self, *args, **kargs):
        # Done for each object; could be done for the class, e.g. with
        # a metaclass
        self._set_attributes(self.__class__, self._attribute_getter)
        Cell.__init__(self, *args, **kargs)
    def _set_attributes(cls, show):
        # We define how cell.a can be used:
        # - for leafs, cell.a is a shortcut for cell['a'].work()/unwork()
        # - for nodes, cell.a gives access to internals, and cell.a.b can
        #   be used in read & write mode.
        for fname, ftype in Attributes._get_members(cls):
            Attributes._set_path(cls, show, fname, fname, ftype)
            if hasattr(cls, '_header') and fname == 'header':
                # Direct access to packet header fields
                for n, t in Attributes._get_members(ftype):
                    Attributes._set_path(cls, show, [fname, n], n, t)
    _set_attributes = staticmethod(_set_attributes)
    def _get_members(cls):
        members = [ ]
        for o in [cls] + getattr(cls, '_options', []):
            if hasattr(o, '_iter_type'):
                members.extend(o._iter_type())
            else:
                # TODO -- LEGACY
                members.extend([ (desc[0], desc[1][0])
                         for desc in getattr(o, '_layout', []) ])
            members.extend([ (name, Leaf)
                for name in getattr(o, '_virtual_fields', []) ])
        return members
    _get_members = staticmethod(_get_members)
    def _set_path(cls, show, fname, sname, ftype):
        # For class cls, define cell.sname to be cell[fname]
        if hasattr(cls, sname):
            # Don't redefine existing attributes; if there is a name
            # collision, the syntax cell[fname] is mandatory.
            return
        if issubclass(ftype, Leaf) or issubclass(ftype, Str):
            getter = lambda self,  name=fname: show(self[name])
            setter = lambda self,v,name=fname: self[name].unwork(v)
        elif issubclass(ftype, Node) or issubclass(ftype, Wrap):
            def getter(s, name=fname):
                cls._set_attributes(s[name].__class__, show)
                return s[name]
            setter = lambda self,v,name=fname: self[name].unwork(v)
        else:
            log.error("UNKNOWN TYPE IS %r", ftype)
        setattr(cls, sname, property(getter, setter, None))
    _set_path = staticmethod(_set_path)

class AttributesElfesteem(Attributes):
    """ Adds compatibility with elfesteem API.
        Cell content can be accessed through attributes, e.g. cell.f
        instead of cell['f'].work()
    """
    def __init__(self, *args, **kargs):
        if 'content' in kargs.keys():
            content = kargs.pop('content')
            parent = kargs.pop('parent')
            start = kargs.pop('start')
            Cell.__init__(self, **kargs)
            self.unpack(content, offset=start)
            return
        Attributes.__init__(self, *args, **kargs)
    def pack(self, **kargs):
        """ Same as Cell.pack(with_holes=True) """
        r = self.binrepr()
        if hasattr(self, 'not_parsed'):
            r[0] = self.not_parsed.data
        return r.pack(**kargs)
    bytelen = property(lambda self: self.packlen())
    def __len__(self):
        return self.bytelen
    _attribute_getter = staticmethod(lambda cell: cell.repr())

class AttributesScapy(Attributes):
    """ Adds compatibility with scapy2 API.
        Similar to AttributesElfesteem, but cell.f returns None if undefined
        and with no default value, instead of returning the generated
        value.
    """
    def _attribute_getter(cell):
        if not hasattr(cell, '_content'):
            return cell.repr()
        if cell._content is not None: return cell._content
        if hasattr(cell, '_default'): return cell.repr2work(cell._default)
        return None
    _attribute_getter = staticmethod(_attribute_getter)

class StackMetaclass(CellMetaclass):
    """ python3 only, the attributes are ordered. """
    def __prepare__(cls, a, b):
        import collections
        return collections.OrderedDict()
    __prepare__ = classmethod(__prepare__)
    def __new__(meta, name, bases, dct):
        assert not '_fields' in dct
        fields = []
        for k, v in list(dct.items()): # list() needed since python3.5
            if isinstance(v, type) and issubclass(v, Cell):
                fields.append( (k, dct.pop(k)) )
        dct['_fields'] = fields
        dct['_check_definition'] = classmethod(lambda _: None)
        return CellMetaclass.__new__(meta, name, bases, dct)
""" Same syntax as StackCell from scapy3 """
StackStruct = StackMetaclass('StackStruct', (Struct,), {})
