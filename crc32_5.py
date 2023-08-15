# -*- coding: utf-8 -*-

import itertools
import binascii
import string


class crc32_reverse_class(object):
    # the code is modified from https://github.com/theonlypwner/crc32/blob/master/crc32.py
    def __init__(self, crc32, length, tbl=string.printable,
                 poly=0xEDB88320, accum=0):
        self.char_set = set(map(ord, tbl))
        self.crc32 = crc32
        self.length = length
        self.poly = poly
        self.accum = accum
        self.table = []
        self.table_reverse = []

    def init_tables(self, poly, reverse=True):
        # build CRC32 table
        for i in range(256):
            for j in range(8):
                if i & 1:
                    i >>= 1
                    i ^= poly
                else:
                    i >>= 1
            self.table.append(i)
        assert len(self.table) == 256, "table is wrong size"
        # build reverse table
        if reverse:
            found_none = set()
            found_multiple = set()
            for i in range(256):
                found = []
                for j in range(256):
                    if self.table[j] >> 24 == i:
                        found.append(j)
                self.table_reverse.append(tuple(found))
                if not found:
                    found_none.add(i)
                elif len(found) > 1:
                    found_multiple.add(i)
            assert len(self.table_reverse) == 256, "reverse table is wrong size"

    def rangess(self, i):
        return ', '.join(map(lambda x: '[{0},{1}]'.format(*x), self.ranges(i)))

    def ranges(self, i):
        for kg in itertools.groupby(enumerate(i), lambda x: x[1] - x[0]):
            g = list(kg[1])
            yield g[0][1], g[-1][1]

    def calc(self, data, accum=0):
        accum = ~accum
        for b in data:
            accum = self.table[(accum ^ b) & 0xFF] ^ ((accum >> 8) & 0x00FFFFFF)
        accum = ~accum
        return accum & 0xFFFFFFFF

    def findReverse(self, desired, accum):
        solutions = set()
        accum = ~accum
        stack = [(~desired,)]
        while stack:
            node = stack.pop()
            for j in self.table_reverse[(node[0] >> 24) & 0xFF]:
                if len(node) == 4:
                    a = accum
                    data = []
                    node = node[1:] + (j,)
                    for i in range(3, -1, -1):
                        data.append((a ^ node[i]) & 0xFF)
                        a >>= 8
                        a ^= self.table[node[i]]
                    solutions.add(tuple(data))
                else:
                    stack.append(((node[0] ^ self.table[j]) << 8,) + node[1:] + (j,))
        return solutions

    def dfs(self, length, outlist=['']):
        tmp_list = []
        if length == 0:
            return outlist
        for list_item in outlist:
            tmp_list.extend([list_item + chr(x) for x in self.char_set])
        return self.dfs(length - 1, tmp_list)

    def run_reverse(self):
        # initialize tables
        self.init_tables(self.poly)
        # find reverse bytes
        desired = self.crc32
        accum = self.accum
        # 4-byte patch
        if self.length >= 4:
            patches = self.findReverse(desired, accum)
            for patch in patches:
                checksum = self.calc(patch, accum)
                print('verification checksum: 0x{0:08x} ({1})'.format(
                    checksum, 'OK' if checksum == desired else 'ERROR'))
            for item in self.dfs(self.length - 4):
                patch = list(map(ord, item))
                patches = self.findReverse(desired, self.calc(patch, accum))
                for last_4_bytes in patches:
                    if all(p in self.char_set for p in last_4_bytes):
                        patch.extend(last_4_bytes)
                        print ('[find]: {1} ({0})'.format(
                            'OK' if self.calc(patch, accum) == desired else 'ERROR', ''.join(map(chr, patch))))
        else:
            for item in self.dfs(self.length):
                if crc32(item) == desired:
                    print ('[find]: {0} (OK)'.format(item))


def crc32_reverse(crc32, length, char_set=string.printable,
                  poly=0xEDB88320, accum=0):
    '''

    :param crc32: the crc32 you wnat to reverse
    :param length: the plaintext length
    :param char_set: char_set
    :param poly: poly , default 0xEDB88320
    :param accum: accum , default 0
    :return: none
    '''
    obj = crc32_reverse_class(crc32, length, char_set, poly, accum)
    obj.run_reverse()


def crc32(s):
    '''

    :param s: the string to calculate the crc32
    :return: the crc32
    '''
    return binascii.crc32(s) & 0xffffffff

if __name__ == '__main__':
    l=[0x397E0355]
    for k in l:
        crc32_reverse(k,5)

