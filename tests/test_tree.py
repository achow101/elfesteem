#! /usr/bin/env python

from test_all import run_tests, hashlib
from elfesteem.core.tree import *

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

def test_insert(assertion):
    """ Search trees implemented as 2-3 trees. """
    t = SearchTree()
    assertion(0, t.depth(),
        'Depth of empty')
    t.insert(2)
    assertion([2], t.x,
        'Insert in empty')
    assertion(1, t.depth(),
        'Depth of size one')
    t.insert(6)
    assertion([2, 6], t.x,
        'Insert in leaf')
    assertion(1, t.depth(),
        'Depth of size two')
    t.insert(5)
    assertion([ [2], 5, [6]], t.x,
        'Insert that creates internal node')
    assertion(2, t.depth(),
        'Depth with internal node')
    t.x = [ [2], 5, [6] ]
    t.insert(9)
    assertion([[2], 5, [6, 9]], t.x,
        'Insert more')
    t.insert(4)
    assertion([[2, 4], 5, [6, 9]], t.x,
        'Normal insertion')
    t.insert(10)
    assertion([[2, 4], 5, [6], 9, [10]], t.x,
        'Insert and split')
    t.insert(1)
    assertion([[[1], 2, [4]], 5, [[6], 9, [10]]], t.x,
        'Insert and add level')
    t = SearchTree()
    for v in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16):
        t.insert(v)
    assertion([[[[1], 2, [3]], 4, [[5], 6, [7]]],
            8, [[[9], 10, [11]], 12, [[13], 14, [15, 16]]]], t.x,
        '16 insertions in increasing order')
    t = SearchTree()
    for v in (6, 1, 15, 3, 11, 12, 4, 5, 7, 8, 16, 9, 10, 13, 2, 14):
        t.insert(v)
    assertion([[[1, 2], 3, [4, 5]], 6, [[7], 8, [9]],
           10, [[11], 12, [13, 14], 15, [16]]], t.x,
        '16 insertions in arbitrary order')
    for v in range(2):
        t.insert(7)
    assertion([[[1, 2], 3, [4, 5]], 6, [[7], 7, [7], 8, [9]],
           10, [[11], 12, [13, 14], 15, [16]]], t.x,
        'Insert duplicate')

def test_find(assertion):
    t = SearchTree()
    t.x = [[[1,2],3,[4,5]],6,[[7],7,[7],8,[9]],10,[[11],12,[13,14],15,[16]]]
    for v in [_+1 for _ in range(16)]:
        assertion(v, t.find(v), 'Element %s in tree (find)'%v)
        assertion(v, t.lfind(v), 'Element %s in tree (lfind)'%v)
    for v in range(16):
        assertion(v+1, t.rfind(v), 'Element %s in tree (rfind)'%v)
    for v in (4.5, 20):
        assertion(None, t.find(v), 'Element %s not in tree'%v)
    for v in [_+1.5 for _ in range(16)]:
        assertion(int(v), t.lfind(v), 'lfind(%s)'%v)
    assertion(None, t.lfind(0.5), 'lfind(0.5)')
    assertion(16, t.lfind(17.5), 'lfind(17.5)')
    for v in [_+0.5 for _ in range(16)]:
        assertion(1+int(v), t.rfind(v), 'rfind(%s)'%v)
    assertion(1, t.rfind(-2), 'rfind(-2)')
    assertion(None, t.rfind(17.5), 'rfind(17.5)')

def test_remove(assertion):
    """
    # TODO : remove nodes from a 2-3 tree; this is a bit subtle
    t = SearchTree()
    t.x = [[[2], 3, [4, 5]], 6, [[7], 8, [9]],
       10, [[11], 12, [13, 14], 15, [16]]]
    print(". %r %r"%(tuple(t),t.x))
    t.pprint()
    t.remove(2)
    print(". %r %r"%(tuple(t),t.x))
    t.pprint()
    t.remove(3)
    print(". %r %r"%(tuple(t),t.x))
    t.pprint()
    
    t.remove(16)
    print(". %r %r"%(tuple(t),t.x))
    t.pprint()
    t.remove(15)
    print(". %r %r"%(tuple(t),t.x))
    t.pprint()
    t.remove(14)
    print(". %r %r"%(tuple(t),t.x))
    t.pprint()
    t.remove(13)
    print(". %r %r"%(tuple(t),t.x))
    t.pprint()
    t.x = [[[1, 2], 3, [4, 5]], 6, [[7], 7, [7], 8, [9]], 10, [[11], None, [12]]]
    print(". %r %r"%(tuple(t),t.x))
    t.pprint()
    """

def run_test(assertion):
    for name, value in dict(globals()).items():
        if name.startswith('test_'):
            value(assertion)

if __name__ == "__main__":
    run_tests(run_test)
