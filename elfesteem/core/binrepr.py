# Binary representation that can deal with sparse or overlapping data.

import struct
from elfesteem.core import tree

class BinChunk(object):
    def __init__(self, pos, data):
        """ A chunk at position 'pos' may have been written multiple times;
            we keep the history of what has been written in a list.
        """
        self.pos = pos
        if not isinstance(data, list): data = [data]
        if not hasattr(data[0], 'decode'): raise TypeError("%s cannot contain %s"
            % (self.__class__.__name__, data[0].__class__.__name__))
        self.data = data
    def __lt__(self, other):
        return self.pos < getattr(other, 'pos', other)
    def __gt__(self, other):
        return self.pos > getattr(other, 'pos', other)
    def __eq__(self, other):
        return self.pos == getattr(other, 'pos', other)
    def __repr__(self):
        if len(self.data) == 1:
            return '%s(%r,%r)'%(self.__class__.__name__, self.pos, self.data[0])
        else:
            return '<%s(%r,%r)>'%(self.__class__.__name__, self.pos, self.data)

class BinRepr(object):
    def __init__(self, *args):
        """ - x=BinRepr() creates an empty object.
            - x=BinRepr(bytestring) creates an object with
              bytestring at offset 0.
            - x[o1:o2]=bytestring replaces the segment between o1 and o2
            - x[o1]=bytestring adds overlapping data starting at o1
            - b=x[o1:o2] returns the byte(s) between o1 and o2;
              fails if there is overlapping
            - b=x[o1] returns the byte at o1
              a list of bytes if there is overlapping
            - x.pack() transforms the object into a bytestring; it fails
              if it is sparse or overlapping, unless:
              'paddingbyte' is defined to fill-in sparse data;
              'overwrite' is defined to choose the most recent segments.
        """
        self.data = tree.SearchTree()
        if len(args) > 1:
            raise ValueError("%s init with at most one parameter"
                % self.__class__.__name__)
        elif len(args) == 1:
            self.data.insert(BinChunk(0, args[0]))
    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.data)
    def bytelen(self):
        sz = 0
        for chunk in self.data:
            eod = chunk.pos + len(chunk.data[-1])
            if eod > sz: sz = eod
        return sz
    def __len__(self):
        return self.bytelen()
    def __iadd__(self, value):
        self[self.bytelen()] = value
        return self
    def __setitem__(self, item, value):
        if type(item) is slice:
            assert item.step is None
            assert item.stop-item.start == len(value)
            self.write_at(item.start, value)
            # Overwrite
            pos = item.start
            while pos < item.stop:
                chunk = self.data.find(pos)
                data = chunk.data[-1]
                chunk.data = [data]
                pos += len(data)
        else:
            if isinstance(value, BinRepr):
                for chunk in value.data:
                    for data in chunk.data:
                        self[item+chunk.pos] = data
            else:
                self.write_at(item, value)
    def write_at(self, pos, data):
        if len(data) == 0:
            return
        nxt = self.data.rfind(pos)
        if nxt is not None and pos+len(data) > nxt.pos:
            # If 'data' is too long and overlaps the next chunk,
            # we do recursive calls, because it may overlap many
            # other chunks.
            self[pos]    = data[:nxt.pos-pos]
            self[nxt.pos] = data[nxt.pos-pos:]
            return
        chunk = self.split_at(pos)
        if chunk is None:
            self.data.insert( BinChunk(pos, data) )
            return
        # Overlapping chunks
        l, ld = len(chunk.data[-1]), len(data)
        if ld > l:
            self.data.insert( BinChunk(pos+l, data[l:]) )
            data = data[:l]
        elif ld < l:
            self.split_at(pos+ld)
        if data != chunk.data[-1]:
            chunk.data.append(data)
    def split_at(self, pos):
        """ Split at position 'pos'. """
        prv = self.data.lfind(pos)
        if prv is None: # 'pos' is before all chunks
            return None
        shift = pos-prv.pos
        if shift == 0: # Already in the tree
            return prv
        if shift >= len(prv.data[-1]): # between chunks of after the last
            return None
        self.data.insert( BinChunk(pos, [_[shift:] for _ in prv.data]) )
        prv.data = [_[:shift] for _ in prv.data]
        return self.data.find(pos)
    def __getitem__(self, item, paddingbyte = -1, overwrite = False):
        if type(item) is slice:
            assert item.step is None
            return self.get_slice(item.start, item.stop)
        else:
            prv = self.data.lfind(item)
            if prv is None: return None
            pos = item - prv.pos
            if len(prv.data[-1]) <= pos: return None
            res = [ _[pos:pos+1] for _ in prv.data ]
            if len(res) == 1: return res[0] # No overlap
            else:             return res    # Overlap
    def get_slice(self, start, stop, paddingbyte = -1, overwrite = False):
        """ Faster than pack() for short slices.
            Complexity linear in the size of the result and logarithmic
            in the size of the tree (linear in its depth).
        """
        res = []
        pos = start
        while pos < stop:
            assert len(res) == pos-start
            prv = self.data.lfind(pos)
            if prv is None or pos-prv.pos >= len(prv.data[-1]):
                res.append(paddingbyte)
                pos += 1
                continue
            if not overwrite and len(prv.data) > 1:
                raise ValueError("Overlapping chunks")
            res += struct.unpack('B', prv.data[-1][pos-prv.pos:1+pos-prv.pos])
            pos += 1
        return struct.pack('%dB'%len(res),*res)
    def pack(self, paddingbyte = -1, overwrite = False):
        """ Faster than get_slice() with long slices.
            Complexity linear in the size of the result.
        """
        res = []
        for chunk in self.data:
            if not overwrite and len(chunk.data) > 1:
                raise ValueError("Overlapping chunks at %d"%chunk.pos)
            assert len(res) <= chunk.pos
            while len(res) < chunk.pos: res.append(paddingbyte)
            data = chunk.data[-1]; l = len(data)
            res[chunk.pos:chunk.pos+l] = struct.unpack('%dB'%l,data)
        return struct.pack('%dB'%len(res),*res)
    def xor(self, arg, offset=0):
        """ Bitwise xor, starting self at some offset. """
        arg = struct.unpack("B"*len(arg),
              arg.pack(paddingbyte=0))
        val = struct.unpack("B"*len(arg),
              self.get_slice(offset, offset+len(arg), paddingbyte=0))
        val = [v^arg[i] for (i,v) in enumerate(val)]
        self[offset:offset+len(val)] = struct.pack("B"*len(val),*val)
        return self
