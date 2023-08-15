import os
from enum import EnumMeta


class Flag(EnumMeta):
    CENTRAL_DIR_FLAG = b'\x50\x4B\x01\x02'
    SOURCE_FILE_FLAG = b'\x50\x4B\x03\x04'
    END_FLAG = b'\x50\x4B\x05\x06'
    DATA_DESCRIPTOR_FLAG = b'\x50\x4B\x07\x08'


class HackerZip:
    @classmethod
    def repair(cls, path, encoding='utf-8'):
        """
        伪加密修复,加密标志中出现了偶数,可能是伪加密
        :param path:
        :return:
        """
        with open(path, 'rb') as f:
            bs = f.read()
        outname, ext = os.path.splitext(path)
        outfile = f"{outname}_repair{ext}"
        out = open(outfile, 'wb')
        toint = lambda x: int.from_bytes(x, byteorder='little')
        while bs:
            signature = bs[:4]
            if signature == Flag.SOURCE_FILE_FLAG:
                header_length = 30
                compression_method = toint(bs[8:10])
                crc = hex(toint(bs[14:18])).upper()
                compressed_size = toint(bs[18:22])
                uncompressed_size = toint(bs[22:26])
                file_name_length = toint(bs[26:28])
                extra_field_length = toint(bs[28:30])
                length = header_length + compressed_size + file_name_length + extra_field_length
                file_name = bs[header_length:header_length + file_name_length].decode(encoding=encoding)
                encrypt_flag = toint(bs[6:8])

                print((f"源文件: {file_name}\n  "
                       f"加密方式: {compression_method} "
                       f"crc: {crc} "
                       f"压缩前size: {uncompressed_size} "
                       f"压缩后size: {compressed_size} "
                       f"加密位: {encrypt_flag} "))
                out.write(bs[:6] + b'\x00\x00' + bs[8:length])
                bs = bs[length:]
            elif signature == Flag.DATA_DESCRIPTOR_FLAG:
                crc = hex(toint(bs[4:8])).upper()
                compressed_size = toint(bs[8:12])
                uncompressed_size = toint(bs[12:16])

                print((f"  文件描述符:\n  "
                       f"crc: {crc} "
                       f"压缩前size: {uncompressed_size} "
                       f"压缩后size: {compressed_size} "))
                out.write(bs[:16])
                bs = bs[16:]
            elif signature == Flag.CENTRAL_DIR_FLAG:
                header_length = 46
                compression_method = toint(bs[10:12])
                crc = hex(toint(bs[16:20])).upper()
                compressed_size = toint(bs[20:24])
                uncompressed_size = toint(bs[24:28])
                dir_name_length = toint(bs[28:30])
                extra_field_length = toint(bs[30:32])
                length = header_length + dir_name_length + extra_field_length
                dir_name = bs[header_length:header_length + dir_name_length].decode(encoding=encoding)
                encrypt_flag = toint(bs[8:10])

                print((f"核心目录: {dir_name}\n  "
                       f"加密方式: {compression_method} "
                       f"crc: {crc} "
                       f"压缩前size: {uncompressed_size} "
                       f"压缩后size: {compressed_size} "
                       f"加密位: {encrypt_flag} "))
                out.write(bs[:8] + b'\x00\x00' + bs[10:length])
                bs = bs[length:]
            elif signature == Flag.END_FLAG:
                total_number_central_directory = toint(bs[10:12])
                size_of_central_directory = toint(bs[12:16])
                offset_of_central_directory = toint(bs[16:20])
                comment_length = toint(bs[20:22])
                comment = bs[22:22 + comment_length].decode()

                print((f"zip结尾:\n  "
                       f"核心目录结构总数: {total_number_central_directory} "
                       f"核心目录大小: {size_of_central_directory} "
                       f"核心目录偏移: {offset_of_central_directory} "
                       f"注释: \n<{comment}>"))
                out.write(bs)
                bs = None
            else:
                raise ValueError('zip格式异常')
        print(outfile)


class HackerRar:
    @classmethod
    def repair(cls, path):
        with open(path, 'rb') as f:
            bs = bytearray(f.read())
            bs[23] = bs[23] & 0xFB
        outname, ext = os.path.splitext(path)
        outfile = f"{outname}_repair{ext}"
        with open(outfile, 'wb') as f:
            f.write(bs)


if __name__ == '__main__':
    HackerRar.repair(path)
