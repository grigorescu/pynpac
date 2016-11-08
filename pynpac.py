#!/usr/bin/env python

from collections import OrderedDict
import json
import logging
import struct

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(module)10s] [%(levelname)5s] %(message)s')

uint8 = "B"
uint16 = "H"
uint32 = "I"
uint64 = "Q"

class Parser(object):
    def __init__(self, f):
        self.f = f
        self.offset = 0
        self.data = Record()

    def parse(self, s):
        size = struct.calcsize(s)
        logging.debug("Parsing %s @%d (size=%d)" % (s, self.offset, size))
        self.offset += size
        return struct.unpack(s, self.f.read(size))[0]

    def jump(self, l):
        logging.debug("Jump requested to %d" % l)
        struct.unpack("%ds" % l, self.f.read(l))
        logging.debug("Jumping %d @%d (to @%d)" % (l, self.offset, self.offset+l))
        self.offset += l

    def print_data(self):
        return json.dumps(self.data, indent=4)

class Record(OrderedDict):
    'Store items in the order the keys were last added'

    def __setitem__(self, key, value):
        logging.debug("Setting %s to %s" % (key, value))
        if key in self:
            del self[key]
        OrderedDict.__setitem__(self, key, value)
