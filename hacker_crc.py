# coding:utf-8
import zipfile
from string import digits, ascii_letters, punctuation
import binascii
from itertools import product
from crc32_6 import init_tables, findReverse, calc
from crc32_5 import crc32_reverse
from functools import lru_cache


class HackerCrc:
    # 爆破字典
    dictionary: str = digits + ascii_letters + punctuation

    def __init__(self):
        self.reslist=[]

    def reverse6(self, crc, char_set=dictionary):
        """6位crc爆破"""
        if isinstance(char_set, str):
            dic = set(map(ord, char_set))
        init_tables(3988292384)
        patches = findReverse(crc, 0)
        for patch in patches:
            print('4 bytes: {{0x{0:02x}, 0x{1:02x}, 0x{2:02x}, 0x{3:02x}}}'.format(*patch))
            checksum = calc(patch, 0)
            print('verification checksum: 0x{0:08x} ({1})'.format(
                checksum, 'OK' if checksum == crc else 'ERROR'))
        # 6-byte alphanumeric patches
        res = []
        for i in dic:
            for j in dic:
                patch = [i, j]
                patches = findReverse(crc, calc(patch, 0))
                for last_4_bytes in patches:
                    if all(p in dic for p in last_4_bytes):
                        patch.extend(last_4_bytes)
                        if calc(patch, 0) == crc:
                            res.append(''.join(list(map(chr, patch))))
        print(f'[find]: {res}')

    @lru_cache(None)
    def getCrc32(self, word):
        return binascii.crc32(word.encode()) & 0xffffffff

    def crack(self, crc, file_size, char_set=dictionary):
        """crc爆破"""
        print(hex(crc))
        for words in product(char_set, repeat=file_size):
            word = ''.join(words)
            if crc == self.getCrc32(word):
                self.reslist.append(word)
                print(f'[find]: {word}')
                break

    def reverse(self, crc, file_size):
        """
        crc破解
        :param crc: crc值, 16进制, 如crc=0x8E234AE0
        :param file_size: 字符长度
        :return:
        """
        if file_size == 6:
            self.reverse6(crc=crc, char_set=self.dictionary)
        elif 4 <= file_size <= 5:
            crc32_reverse(crc32=crc, length=file_size, char_set=self.dictionary)
        elif file_size <= 3:
            self.crack(crc=crc, file_size=file_size, char_set=self.dictionary)

    def crackZip(self, path):
        """按文件爆破"""
        zf = zipfile.ZipFile(path)
        for f in zf.filelist:
            if f.filename.endswith('.txt'):
                print(f"-------------------{f.filename}--------------------")
                self.reverse(f.CRC, f.file_size)
        print(''.join(self.reslist))

    def test(self):
        crcs = {3: 0x1AA8DB2B, 4: 0xC4E68E3A, 5: 0X05DEC988, 6: 0X8E234AE0}
        for length, crc in crcs.items():
            self.reverse(crc, length)


if __name__ == '__main__':
    h = HackerCrc()
    h.test()
