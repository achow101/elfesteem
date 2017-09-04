# Implementation of 2-3 trees

import struct, sys

# reversed, set and others appeared in python 2.4
try:
    reversed([])
    set = set
except NameError:
    import warnings
    warnings.simplefilter("ignore", FutureWarning)
    def reversed(l):
        length = len(l)
        return [ l[length-idx] for idx in range(1,length+1) ]
    def sorted(l, key=None, reverse=False):
        l = [_ for _ in l]
        if key is None:
            if reverse: l.sort(lambda x,y: cmp(y,x))
            else:       l.sort()
        else:
            if reverse: l.sort(lambda x,y: cmp(key(y),key(x)))
            else:       l.sort(lambda x,y: cmp(key(x),key(y)))
        return l
    class set(dict):
        # Implementation of sets, based on dictionaries. Fast
        def __init__(self, init=[]):
            self.update(init)
        def copy(self):
            return set(self.keys())
        def pop(self):
            return self.popitem()[0]
        def add(self, item):
            self[item] = True
        def remove(self, item):
            del self[item]
        def discard(self, item):
            if item in self:
                del self[item]
        def update(self, other):
            for item in other:
                self.add(item)
        def intersection_update(self, other):
            keys = self.keys()
            for item in keys:
                if not item in other:
                    del self[item]
        def difference_update(self, other):
            for item in other:
                self.discard(item)
        def union(self, other):
            result = set(self.keys())
            result.update(other)
            return result
        def intersection(self, other):
            result = set()
            for item in self:
                if item in other:
                    result.add(item)
            return result
        def difference(self, other):
            result = set()
            for item in self:
                if not item in other:
                    result.add(item)
            return result

class SearchTree(object):
    """ Implemented as 2-3 trees. """
    # Empty     []
    # 1         [ 1 ]
    # 1 2 3 4   [ [1] 2 [3 4] ]  2-node
    # 1 2 3 4 5 [ [1] 2 [3] 4 [5] ]  3-node
    def __init__(self, compare=lambda a, b: a < b):
        self.x = []
        self.cmp = compare
    def __iter__(self):
        """ Iterates over all elements, in increasing order. """
        # We reverse self.x to avoid copying stack at each iteration
        r, stack = [], list(reversed(self.x))
        while len(stack):
            v = stack.pop()
            if isinstance(v, list): stack.extend(reversed(v))
            else:                   yield v
    def __str__(self):
        return repr(self.x)
    def pprint(self):
        """ Pretty-printing. """
        return "\n".join(self._pprint(self.x))
    def _pprint(self, node, shift=0):
        if   len(node) == 0:
            return []
        elif len(node) == 1:
            return [ "   "*shift+"%3s"%node[0] ]
        elif len(node) == 2:
            return [ "   "*shift+"%3s"%node[0],
                     "   "*shift+"%3s"%node[1] ]
        elif len(node) == 3:
            return self._pprint(node[0], shift=shift+1) + \
                   [ "   "*shift+"%3s"%node[1] ] + \
                   self._pprint(node[2], shift=shift+1)
        else:
            return self._pprint(node[0], shift=shift+1) + \
                   [ "   "*shift+"%3s"%node[1] ] + \
                   self._pprint(node[2], shift=shift+1) + \
                   [ "   "*shift+"%3s"%node[3] ] + \
                   self._pprint(node[4], shift=shift+1)
    def depth(self):
        """ Returns the depth of the 2-3 tree. """
        return self._depth(self.x)
    def _depth(self, node):
        if not isinstance(node, list): return 0
        elif len(node) == 0:           return 0
        else:                          return 1 + self._depth(node[0])
    def find(self, key):
        """ Returns the first element equal to 'key', None is there is none. """
        return self._find([self.x], 0, key)
    def _find(self, node, idx, key):
        cell = node[idx]
        if   len(cell) == 0:            # Empty tree
            return None
        elif isinstance(cell[0], list): # Internal node
            if   cell[1] >  key: return self._find(cell, 0, key)
            elif cell[1] == key: return cell[1]
            elif len(cell) == 3: return self._find(cell, 2, key)
            elif cell[3] >  key: return self._find(cell, 2, key)
            elif cell[3] == key: return cell[3]
            else:                return self._find(cell, 4, key)
        else:                           # Leaf
            if   cell[0] == key: return cell[0]
            elif len(cell) == 1: return None
            elif cell[1] == key: return cell[1]
            else:                return None
    def lfind(self, key):
        """ Returns the biggest element less or equal to 'key', or None. """
        return self._lfind([self.x], 0, key, None)
    def _lfind(self, node, idx, key, dft):
        cell = node[idx]
        if   len(cell) == 0:            # Empty tree
            return dft
        elif isinstance(cell[0], list): # Internal node
            if   cell[1] >  key: return self._lfind(cell, 0, key, dft)
            elif cell[1] == key: return cell[1]
            elif len(cell) == 3: return self._lfind(cell, 2, key, cell[1])
            elif cell[3] >  key: return self._lfind(cell, 2, key, cell[1])
            elif cell[3] == key: return cell[3]
            else:                return self._lfind(cell, 4, key, cell[3])
        else:                           # Leaf
            if   cell[0] >  key: return dft
            elif len(cell) == 1: return cell[0]
            elif cell[1] >  key: return cell[0]
            else:                return cell[1]
    def rfind(self, key):
        """ Returns the smallest element strictly greater than 'key'. """
        return self._rfind([self.x], 0, key, None)
    def _rfind(self, node, idx, key, dft):
        cell = node[idx]
        if   len(cell) == 0:            # Empty tree
            return dft
        elif isinstance(cell[0], list): # Internal node
            if   cell[1] >  key: return self._rfind(cell, 0, key, cell[1])
            elif len(cell) == 3: return self._rfind(cell, 2, key, dft)
            elif cell[3] >  key: return self._rfind(cell, 2, key, cell[3])
            else:                return self._rfind(cell, 4, key, dft)
        else:                           # Leaf
            if   cell[0] >  key: return cell[0]
            elif len(cell) == 1: return dft
            elif cell[1] >  key: return cell[1]
            else:                return dft
    def insert(self, key):
        """ Insert in the tree; if there are other elements with the same
            value, this one is inserted after them. """
        self.x = [self.x]
        self._insert(self.x, 0, key)
        if len(self.x) == 1: self.x = self.x[0]
    def _insert(self, node, idx, key):
        cell = node[idx]
        if   len(cell) == 0:            # Empty tree
            cell[0:0] = [key]
        elif isinstance(cell[0], list): # Internal node
            if   cell[1] >  key: self._insert(cell, 0, key)
            elif len(cell) == 3: self._insert(cell, 2, key)
            elif cell[3] >  key: self._insert(cell, 2, key)
            else:                self._insert(cell, 4, key)
        else:                           # Leaf
            if   cell[0] >  key: cell[0:0] = [key]
            elif len(cell) == 1: cell[1:1] = [key]
            elif cell[1] >  key: cell[1:1] = [key]
            else:                cell[2:2] = [key]
        # The node may need to be split
        if not isinstance(cell[0], list) and len(cell) == 3:
            node[idx:idx+1] = [[cell[0]], cell[1], [cell[2]]]
        elif len(cell) == 7:
            node[idx:idx+1] = [cell[0:3],cell[3],cell[4:7]]
    # This implementation of 'remove' is very incomplete, but remove is not
    # needed for most applications of 2-3 trees.
    def remove(self, key):
        return self._remove([self.x], 0, key)
    def _remove(self, node, idx, key):
        cell = node[idx]
        if   len(cell) == 0:            # Empty tree
            return False
        elif isinstance(cell[0], list): # Internal node
            if   cell[1] >  key: self._remove(cell, 0, key)
            elif cell[1] == key: YU
            elif len(cell) == 3: self._remove(cell, 2, key)
            elif cell[3] >  key: self._remove(cell, 2, key)
            elif cell[3] == key: YV
            else:                self._remove(cell, 4, key)
        else:                           # Leaf
            if   cell[0] == key: cell[0:1] = []
            elif len(cell) == 1: pass
            elif cell[1] == key: cell[1:2] = []
            else:                pass
        print("AFTER %r - %r" % (node, node[idx]))
        # The node may need to be merged
        if   len(cell) == 0 and idx == 4 and len(node[2]) == 2:
            node[2:5] = [[node[2][0]], node[2][1], [node[3]]]
            # [[11], 12, [13, 14], 15, []]
            # [[11], 12, [13], 14, [15]]
        elif len(cell) == 0 and idx == 4 and len(node[2]) == 1:
            node[2:5] = [node[2]+[node[3]]]
            # [[11], 12, [13], 14, []]
            # [[11], 12, [13, 14]]
        elif len(cell) == 0 and idx == 0 and len(node[2]) == 2:
            node[0:3] = [[node[1]], node[2][0], [node[2][1]]]
        else:
            # [[11], 12, []]
            pass
            # [[[1, 2], 3, [4, 5]], 6, [[7], 7, [7], 8, [9]], 10, [[11], 12, []]]
            # [[[1, 2], 3, [4, 5]], 6, [[7], 7, [7], 8, [9]], 10, [[11], None, [12]]]
        print("====> %r" % node)
