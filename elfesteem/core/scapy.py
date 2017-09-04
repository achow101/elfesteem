# Partial API compatibility with scapy2

from elfesteem.core.cell import *

# A network layer is made of a header followed by a payload, and possibly
# by a trailer. The payload is of undetermined type, often a network layer.

class RawPayload(Data):
    _default = struct.pack('')
    def scapy_repr(self):
        val = self.work()
        if not len(val): return ''
        if not isinstance(val, str): val = val.decode('latin1') # python3
        return "<Raw  load=%r |>" % val

def bind_layers(pkt, pay, **kargs):
    # Bindings restrict the type of payload, depending on some fields
    # in the headers, and set default values for some fields, depending
    # on the payload type.
    # This could/should be unified with the constraint system.
    if not hasattr(pkt, '_bindings'): pkt._bindings = {}
    assert not (pay in pkt._bindings)
    pkt._bindings[pay] = kargs

class Payload(Union):
    _fallback = RawPayload
    _options = [ ]
    def unwork(self, value):
        Union.unwork(self, value)
        # Bindings change the value of the underlayer, when not already set
        underlayer = self._parent
        bindings = underlayer._bindings.get(self._wrapped.__class__, {})
        for name, value in bindings.items():
            if not underlayer['header'][name].isdef():
                underlayer['header'][name].unrepr(value)
        return self
    def unpack(self, value, **kargs):
        # Not a standard Union: bindings restrict the possible payloads
        _options = []
        underlayer = self._parent
        for t in getattr(underlayer, '_bindings', []):
            for n, v in underlayer._bindings[t].items():
                if v != underlayer['header'][n].work():
                    break
            else:
                _options.append(t)
        for t in _options + [ self._fallback ]:
            try:
                self._wrapped = t(_parent=self).unpack(value, **kargs)
                return self
            except CellError:
                pass
        return self

class Scapy(AttributesScapy):
    __repr__    = lambda self: self.scapy_repr()
    def _scapy_repr(val):
        if isinstance(val, Array):
            return '[%s]' % ", ".join([_.scapy_repr() for _ in val])
        elif hasattr(val, 'scapy_repr'):
            return val.scapy_repr()
        else:
            return str(val.repr())
    _scapy_repr = staticmethod(_scapy_repr)
    def scapy_repr(self):
        if isinstance(self, Wrap):
            return Scapy._scapy_repr(self._wrapped)
        res = '<%s  ' % self.__class__.__name__
        if isinstance(self, Layer):
            cell = self['header']
            payload = self['payload']._wrapped.scapy_repr()
        else:
            cell = self
            payload = ''
        for fname in cell._iter_name():
            val = cell[fname]
            if val.isdef():
                res += '%s=%s ' % (fname, Scapy._scapy_repr(val))
        return res + '|' + payload + '>'

class Layer(Scapy,Struct):
    __div__     = lambda self, payload: self.add_payload(payload) # for python2
    __truediv__ = lambda self, payload: self.add_payload(payload) # for python3
    __str__     = lambda self: self.pack() # python2 only: returns bytes in python3
    def _update_dct(cls, name, dct):
        Header = Struct[dct['_header']]
        dct['_fields'] = [
            ('header', Header),
            ('payload', Payload),
            ]
        dct['_bindings'] = {}
    _update_dct = classmethod(_update_dct)
    def _check_definition(cls):
        if cls.__name__ != 'Layer':
            Payload._options.append(cls)
    _check_definition = classmethod(_check_definition)
    def _unwork_unrepr(self, value, wrapped_function):
        if wrapped_function == 'unrepr' and value is not None:
            header = dict(value)
            payload = header.pop('payload',None)
            value = { 'payload': payload, 'header': header }
        Struct._unwork_unrepr(self, value, wrapped_function)
    def work2repr(self, val):
        ret = {'payload':val['payload']}
        ret.update(self['header'].work2repr(val['header']))
        return ret
    def __getitem__(self, item):
        if isinstance(item, type) and issubclass(item, Layer):
            while isinstance(self, Layer):
                if isinstance(self, item): return self
                self = self['payload']._wrapped
            raise KeyError("Layer [%s] not found"%item.__name__)
        return Struct.__getitem__(self, item)
    def add_payload(self, payload):
        if self['payload'].isdef():
            # Change of precedence of __div__ such that A/B/C means A/(B/C)
            self['payload']._wrapped.add_payload(payload)
        elif isinstance(payload, Layer):
            self['payload'].unwork(payload)
        else:
            self['payload'].unpack(payload)
        return self
