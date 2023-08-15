import base64
import binascii
import re
from basecrack.basecrack import BaseCrack
import logging

logging.basicConfig(level=logging.INFO,
                    # filename="base.log",
                    format="[%(asctime)s] %(message)s")
logger = logging.getLogger(__name__)


class HackerBase:

    def decode(self, base_str, deep=0):
        bases = {
            "base16": {
                'decode': base64.b16decode,
                'pattern': "^[0-9A-F]+$"
            },
            "base32": {
                'decode': base64.b32decode,
                'pattern': "^[A-Z2-7]+={0,6}$"
            },
            "base64": {
                'decode': base64.b64decode,
                'pattern': "^[A-Za-z0-9+/]+={0,2}$"
            },
            "base85": {
                'decode': base64.b85decode,
                'pattern': '^[0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~]+$'
            }
        }

        for base, cfg in bases.items():
            if isinstance(base_str, str) and re.match(cfg['pattern'], base_str):
                try:
                    res = cfg['decode'](base_str.encode()).decode()
                    self.decode(res, deep + 1)
                    logger.info(f"{''.join(['>'] * deep)}{base}: {res}")
                except:
                    pass

    def dfs_decode(self, base_str):
        base_str = base_str.strip()

        def dfs(base_str):
            res = BaseCrack().decode(base_str)
            while res:
                logger.info(f"{res[1]}: {res[0]}")
                res = BaseCrack().decode(res[0])

        dfs(base_str)
        dfs(base_str.lower())
        dfs(base_str.upper())

    def magic(self, base_str):
        base_str = base_str.strip()
        BaseCrack().magic_mode(base_str)

    def trans(self):
        """按new字典表生成base64"""
        s = b"YmxGY3s3MnMnYjd3Y2X5XWM5YfpoXWQkNSMlMzMnYjl9"
        old = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        new = b'/abcdefghIJKLMNOPQRSTUVWXYZABCDEFGijklmnopqrstuvwxyz0123456789+='
        s = s.translate(bytes.maketrans(new, old))
        print(binascii.a2b_base64(s))


if __name__ == '__main__':
    s = """U2EkVFu77HRQHxBsKCJs2l/TPXtXSXUpbGRiafVnoUfWq0BCEmYm4jc1b1NEcdFMJEDNRcvJbGPK4LBXWGPOG1+s1NKS7nBywl+mXGMHOP1PREbgwjhg2KoBSGDlVI3xZMNUsDJdsODwKTnr0wxicw=="""
    HackerBase().decode(s)
    HackerBase().dfs_decode(s)
    HackerBase().magic(s)
