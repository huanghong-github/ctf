import binascii
import os
import string
import struct
import base64
import re

from PIL import Image, ImageSequence
from matplotlib import pyplot as plt
import logging
from subprocess import PIPE, Popen, STDOUT
import numpy as np
from io import BytesIO
from path import Path
from cloacked_pixel_master import lsb

import binwalk

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s")
logger = logging.getLogger(__name__)


MISC_DIR = ""

config = {
    "stegsolve": MISC_DIR / "Stegsolve" / "stegsolve.jar",
    "stegdetect": MISC_DIR / "stegdetect-0.4-for-Windows" / "stegdetect.exe",
    "stegbreak": [
        MISC_DIR / "stegdetect-0.4-for-Windows" / "stegbreak.exe",
        MISC_DIR / "stegdetect-0.4-for-Windows" / "'rules.ini",
        MISC_DIR / "stegdetect-0.4-for-Windows" / "password.txt",
    ],
    "blindWatermark": MISC_DIR / "BlindWatermark.jar",
    "steghide": MISC_DIR / "steghide" / "steghide.exe",
}


class HackerImage:
    def __init__(self, path):
        self.path = Path(path)
        self.file_name, self.ext = self.path.basename().splitext()
        
        self.bs = self.path.read_bytes()
        
        self.tmp=Path("tmp")
        if not self.tmp.exists():
            self.tmp.mkdir()

    def show(self, imdata):
        im = Image.open(imdata)
        plt.imshow(im)
        plt.show()

    def shell(self, cmd):
        with Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT) as p:
            content = str(p.stdout.read(), "gbk")
            return content

    def png_repairHW(self):
        """
        宽高改写爆破
        :param bs:
        :return:
        """
        # Iwidth = IHDR[4:8]
        # Iheight = IHDR[8:12]
        IHDR = self.bs[12:33]
        Icrc = IHDR[-4:]
        Icrcdata = int(Icrc.hex(), 16)
        # 宽度，暴力猜解
        bs2 = None
        for i in range(65536):
            width = struct.pack(">i", i)
            data = IHDR[:4] + width + IHDR[8:17]
            crc32result = binascii.crc32(data) & 0xFFFFFFFF
            if crc32result == Icrcdata:
                bs2 = self.bs[:16] + width + self.bs[20:]
                break

        # 高度，暴力猜解
        for i in range(65536):
            height = struct.pack(">i", i)
            data = IHDR[:8] + height + IHDR[12:17]
            crc32result = binascii.crc32(data) & 0xFFFFFFFF
            if crc32result == Icrcdata:
                bs2 = self.bs[:20] + height + self.bs[24:]
                break

        if bs2:
            self.show(BytesIO(bs2))
            return True
        else:
            return False

    def base2image(self):
        """
        base64转图片
        :param bs:
        :return:
        """
        pattern = b"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$"
        if re.match(pattern, self.bs):
            self.show(BytesIO(base64.b64decode(self.bs)))
            return True
        return False

    def javaBlindWatermark(self):
        """java盲水印"""
        BlindWatermark = config.get("blindWatermark")
        cmd = f"java -jar {BlindWatermark} decode -c {self.path} tmp/{self.path.basename()} >nul 2>&1"
        status = os.system(cmd)
        if status == 0:
            self.show(self.tmp/self.path.basename())

    def gif_split(self):
        """
        gif拆分
        :param path:
        :return:
        """
        im = Image.open(self.path)
        pic_dir = self.tmp/self.file_name
        if not pic_dir.exists():
            pic_dir.mkdir()

        im_iter = ImageSequence.Iterator(im)
        for index, frame in enumerate(im_iter):
            logger.info(f"image {index}: mode {frame.mode}, size {frame.size}")
            frame.save(f"tmp/{self.file_name}/frame{index}.png")

    def png_analyse(self):
        """png"""
        print("Header: ", binascii.hexlify(self.bs[0:8]))
        IHDR_len = int.from_bytes(self.bs[8:12], byteorder="big")
        # print("IHDR对应二进制: ", binascii.b2a_hex('IHDR'.encode()))
        print("IHDR", binascii.hexlify(self.bs[12:16]), end=": ")
        print(binascii.hexlify(self.bs[16 : 16 + IHDR_len]))
        print("Width: ", int.from_bytes(self.bs[16:20], byteorder="big"))
        print("Height: ", int.from_bytes(self.bs[20:24], byteorder="big"))
        print("CRC: ", binascii.hexlify(self.bs[16 + IHDR_len : 20 + IHDR_len]))
        print("IDAT对应二进制: ", binascii.b2a_hex("IDAT".encode()))
        idat = re.finditer(pattern=b".{4}IDAT", string=self.bs)
        for i, match in enumerate(idat):
            match = match.group()
            print(f"IDAT{i}: ", binascii.hexlify(match))
            print(
                f"IDAT{i} length: ",
                int.from_bytes(match.rstrip(b"IDAT"), byteorder="big"),
            )

    def jpg_analyse(self):
        """jpg"""
        print("Header: ", binascii.hexlify(self.bs[0:3]))
        idx = self.bs.find(b"\xFF\xC0")
        print("h: ", binascii.hexlify(self.bs[idx + 5 : idx + 7]))
        print(int.from_bytes(self.bs[idx + 5 : idx + 7], byteorder="big"))

        print("w: ", binascii.hexlify(self.bs[idx + 7 : idx + 9]))
        print(int.from_bytes(self.bs[idx + 7 : idx + 9], byteorder="big"))

    def file_analyse(self):
        """文件分析"""
        s = self.bs.decode(errors="ignore")
        keys = ["flag", "ctf", "==", "password"]
        for match in re.finditer(f"[\w{string.printable}]+", s.replace("\n", " ")):
            x = match.group().lower().strip()
            for key in keys:
                if key in x:
                    print(x)

    def steghide(self, password=None):
        """steghide"""
        steghide_exe = config.get("steghide")
        if password is None:
            cmd = f'{steghide_exe} info {self.path} -p ""'
            print(self.shell(cmd))
        else:
            cmd = f'{steghide_exe} extract -sf {self.path} -p "{password}"'
            res = self.shell(cmd)
            # print(res)
            if "not extract" not in res:
                print(password)
                print(res)

    def lsb(self, password=None):
        """lsb"""
        if password is None:
            lsb.analyse(self.path)
        else:
            lsb.extract(self.path, "tmp/flag.txt", password)

    def binwalk(self):
        """binwalk"""
        binwalk.scan(self.path, signature=True, extract=True, directory="tmp")

    def exif(self):
        """exif"""
        im = Image.open(self.path)
        if hasattr(im, "_getexif"):
            info = im.getexif()
            print(info)

    def repair(self):
        if self.ext == ".gif":
            logger.info("----- gifsplit -----")
            self.gif_split()
            return

        if self.ext == ".png":
            logger.info("----- png_analyse -----")
            self.png_analyse()

            logger.info("----- repairHW -----")
            try:
                Image.open(self.path)
            except Image.UnidentifiedImageError:
                if self.png_repairHW():
                    return

        if self.ext == ".jpg":
            logger.info("----- jpg_analyse -----")
            self.jpg_analyse()

            logger.info("----- steghide -----")
            self.steghide()

        logger.info("----- base -----")
        if self.base2image():
            return

        logger.info("----- binwalk -----")
        self.binwalk()

        logger.info("----- exif -----")
        self.exif()

        logger.info("----- lsb -----")
        self.lsb()

        logger.info("----- javaBlindWatermark -----")
        self.javaBlindWatermark()

        logger.info("----- file_analyse -----")
        self.file_analyse()

        logger.info("----- stegsolve -----")
        self.stegsolve()

    def stegsolve(self):
        self.shell(f"{config.get('stegsolve')} {self.path}")

    def stegdetect(self, password=None):
        if password is None:
            stegdetect_exe = config.get("stegdetect")
            cmd = f"{stegdetect_exe} -tjopi -s 10.0 {self.path}"
            print(self.shell(cmd))
        else:
            stegbreak_exe, rule, password = config.get("stegbreak")
            cmd = f"{stegbreak_exe} -r {rule} -f {password} -t p {self.path}"
            print(self.shell(cmd))


if __name__ == "__main__":
    HackerImage(path).repair()
