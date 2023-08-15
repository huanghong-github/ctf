import fire
import os
from pyzbar import pyzbar
from PIL import ImageGrab, ImageEnhance


def read_qrcode():
    """
    二维码读取
    :return:
    """
    shot = os.path.sep.join([os.path.abspath(os.path.curdir), 'static', 'Snapshot.exe'])
    os.system(shot)
    im = ImageGrab.grabclipboard()
    if im:
        im = ImageEnhance.Brightness(im).enhance(2.0)  # 增加亮度
        im = ImageEnhance.Sharpness(im).enhance(17.0)  # 锐利化
        im = ImageEnhance.Contrast(im).enhance(4.0)  # 增加对比度
        im = im.convert('L')  # 灰度图像
        im = im.convert('1')  # 二值图像
        # im.show()
        res = pyzbar.decode(im, symbols=[pyzbar.ZBarSymbol.QRCODE])
        if res:
            res = res[0].data
            if isinstance(res, bytes):
                res = res.decode()
            print(res)
    pass


if __name__ == '__main__':
    fire.Fire(read_qrcode)
