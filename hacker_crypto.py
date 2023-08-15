from brainfuck import brainfuck
from libnum import n2s, s2n,s2b,b2s
from string import ascii_lowercase
from urllib.parse import unquote, quote
from pycipher import Atbash
ord_a = 97
ord_A = 65


class Caesar:
    """凯撒密码"""

    @classmethod
    def encrypt(cls, message, key):
        def fun(c):
            if 'A' <= c <= 'Z':
                return chr((ord(c) - ord_A + key) % 26 + ord_A)
            elif 'a' <= c <= 'z':
                return chr((ord(c) - ord_a + key) % 26 + ord_a)
            else:
                return c

        return "".join([fun(c) for c in message])

    @classmethod
    def decrypt(cls, cryptograph, key):
        def fun(c):
            if 'A' <= c <= 'Z':
                return chr((ord(c) - ord_A - key) % 26 + ord_A)
            elif 'a' <= c <= 'z':
                return chr((ord(c) - ord_a - key) % 26 + ord_a)
            else:
                return c

        return "".join([fun(c) for c in cryptograph])

    @classmethod
    def decrypt_all(cls, cryptograph):
        return [cls.decrypt(cryptograph, i) for i in range(26)]


class Vigenere:
    """维吉尼亚密码
    https://atomcated.github.io/Vigenere/
    """

    @classmethod
    def encrypt(cls, message, key):
        res = []
        i = 0
        for c in message:
            if 'a' <= c <= 'z':
                res.append(chr((ord(c) + ord(key[i % len(key)].lower()) - 2 * ord_a) % 26 + ord_a))
                i += 1
            elif 'A' <= c <= 'Z':
                res.append(chr((ord(c) + ord(key[i % len(key)].upper()) - 2 * ord_A) % 26 + ord_A))
                i += 1
            else:
                res.append(c)
        return "".join(res)

    @classmethod
    def decrypt(cls, cryptograph, key):
        res = []
        i = 0
        for c in cryptograph:
            if 'a' <= c <= 'z':
                res.append(chr((ord(c) - ord(key[i % len(key)].lower())) % 26 + ord_a))
                i += 1
            elif 'A' <= c <= 'Z':
                res.append(chr((ord(c) - ord(key[i % len(key)].upper())) % 26 + ord_A))
                i += 1
            else:
                res.append(c)
        return ''.join(res)


class Affine:
    """仿射密码"""

    @classmethod
    def encrypt(cls, message, a, b):
        fun = lambda c: chr(((ord(c) - ord_a) * a + b) % 26 + ord_a) if 'a' <= c <= 'z' else c
        return "".join([fun(c) for c in message.lower()])

    @classmethod
    def decrypt(cls, cryptograph, a, b):
        fun = lambda c: chr(((ord(c) - ord_a - b) * (26 - a)) % 26 + ord_a) if 'a' <= c <= 'z' else c
        return "".join([fun(c) for c in cryptograph.lower()])


class RailFence:
    """栅栏密码"""

    @classmethod
    def encrypt(cls, message, key):
        message = message.replace(' ', '')
        res = []
        for i in range(key):
            res.extend([c for j, c in enumerate(message) if j % key == i])
        return ''.join(res)

    @classmethod
    def decrypt(cls, cryptograph, key):
        seglen, othlen = divmod(len(cryptograph), key)
        ml = list(cryptograph)
        other = [ml.pop(i * seglen) for i in range(1, othlen + 1)]
        res = [ml[j * seglen + i] for i in range(seglen) for j in range(key)]
        return ''.join(res + other)

    @classmethod
    def decrypt_all(cls, cryptograph):
        return [cls.decrypt(cryptograph, i) for i in range(1, len(cryptograph) // 2)]


class Morse:
    """摩斯密码"""
    MORSE_CODE = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G",
        "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N",
        "---": "O", ".--．": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z",

        "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
        ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",

        # ".-.-.-": ".", "---...": ":", "--..--": ",", "-.-.-.": ";", "..--..": "?",
        # "-...-": "=", ".----.": "'", "-..-.": "/", "-.-.--": "!", "-....-": "-",
        # "..--.-": "_", ".-..-.": '"', "-.--.": "(", "-.--.-": ")", "...-..-": "$",
        # "....": "&", ".--.-.": "@", ".-.-.": "+",
    }

    @classmethod
    def encrypt(cls, message: str, sep='/'):
        mr = {j: i for i, j in cls.MORSE_CODE.items()}
        res = [mr.get(i, i) for i in message.upper()]
        return sep.join(res)

    @classmethod
    def decrypt(cls, cryptograph: str, sep='/'):
        ml = cryptograph.strip().upper().replace('\n', '').split(sep)
        res = [cls.MORSE_CODE.get(i, ' None ') for i in ml]
        return ''.join(res)


class Bacon:
    """培根密码"""
    BACON_CODE = dict(
        A='aaaaa', B='aaaab', C='aaaba', D='aaabb', E='aabaa', F='aabab',
        G='aabba', H='aabbb', I='abaaa', J='abaab', K='ababa', L='ababb',
        M='abbaa', N='abbab', O='abbba', P='abbbb', Q='baaaa', R='baaab',
        S='baaba', T='baabb', U='babaa', V='babab', W='babba', X='babbb',
        Y='bbaaa', Z='bbaab',
        a='AAAAA', g='AABBA', n='ABBAA', t='BAABA', b='AAAAB', h='AABBB',
        o='ABBAB', u='BAABB', c='AAABA', i='ABAAA', j='ABAAA', p='ABBBA',
        d='AAABB', k='ABAAB', q='ABBBB', x='BABAB', e='AABAA', l='ABABA',
        r='BAAAA', y='BABBA', f='AABAB', m='ABABB', s='BAAAB', z='BABBB',
        v='BAABB', w='BABAA'
    )

    @classmethod
    def encrypt(cls, message: str):
        res = [cls.BACON_CODE.get(i, i) for i in message]
        return ''.join(res)

    @classmethod
    def decrypt(cls, cryptograph: str):
        cryptograph = cryptograph.strip()
        ml = [cryptograph[i:i + 5] for i in range(0, len(cryptograph), 5)]
        bc = {j: i for i, j in cls.BACON_CODE.items()}
        res = [bc.get(i) for i in ml]
        return ''.join(res)


class Rot13:
    @classmethod
    def encrypt(cls, message: str):
        return Caesar.encrypt(message, 13)

    @classmethod
    def decrypt(cls, cryptograph: str):
        return Caesar.decrypt(cryptograph, 13)


class Rot18:
    @classmethod
    def encrypt(cls, message: str):
        s = Caesar.encrypt(message, 13)

        def fun(c):
            if '0' <= c <= '9':
                return chr((ord(c) - ord('0') + 5) % 10 + ord('0'))
            else:
                return c

        return "".join([fun(c) for c in s])

    @classmethod
    def decrypt(cls, cryptograph: str):
        s = Caesar.decrypt(cryptograph, 13)

        def fun(c):
            if '0' <= c <= '9':
                return chr((ord(c) - ord('0') - 5) % 10 + ord('0'))
            else:
                return c

        return "".join([fun(c) for c in s])


class Rot47:
    """用于ROT47编码的字符其ASCII值范围是33－126"""

    @classmethod
    def encrypt(cls, message: str):
        return ''.join([chr((ord(i) - 33 - 47) % 92 + 35) for i in message])

    @classmethod
    def decrypt(cls, cryptograph: str):
        return ''.join([chr((ord(i) - 33 + 47) % 92 + 31) for i in cryptograph])


class Ascii:
    @classmethod
    def encrypt(cls, message: str):
        return hex(s2n(message))

    @classmethod
    def decrypt(cls, cryptograph: str, base=16):
        return n2s(int(cryptograph, base)).decode()


class Shift:
    """简单移位密码
    key='3124'
    每4位按3124的顺序重组
    """

    @classmethod
    def decrypt(cls, cryptograph, key):
        cl, kl = len(cryptograph), len(key)
        res = ''
        for i in range(0, cl, kl):
            if cl - i < kl:
                tmp = [''] * kl
                for j in range(cl - i):
                    tmp[int(key[j]) - 1] = cryptograph[i + j]
                res += ''.join(tmp)
            else:
                for j in key:
                    res += cryptograph[i + int(j) - 1]
        return res


class C01248:
    """云影密码
    0用来分割，1248组成数字，对应下标
    """

    @classmethod
    def decrypt(cls, cryptograph):
        idx = [sum(map(int, num)) for num in cryptograph.split('0')]
        res = [ascii_lowercase[i - 1] for i in idx]
        return ''.join(res)


class UrlEncode:
    @classmethod
    def encrypt(cls, message):
        return quote(message)

    @classmethod
    def decrypt(cls, cryptograph):
        return unquote(cryptograph)


class Unicode:
    @classmethod
    def encrypt(cls, message):
        return message.encode('Unicode_escape')

    @classmethod
    def decrypt(cls, cryptograph):
        return cryptograph.decode('Unicode_escape')

class Hill:
    @classmethod
    def decrypt(cls,key,cryptograph):
        import numpy as np
        cryptograph = [(ord(i)-ord_a)%26 for i in cryptograph]
        key=np.array(key).reshape((len(key)//len(cryptograph),len(cryptograph)))
        res=[chr(i%26+ord_a) for i in cryptograph@key]
        return res

def burst():
    import hashlib
    import itertools
    import string
    for i in itertools.product(string.printable, repeat=4):
        a = '%s7%s5-%s4%s3?' % i
        sha = hashlib.sha1(a.encode())
        s = sha.hexdigest()
        if "619c20c" and "a4de755" and "9be9a8b" and "b7cbfa5" and "e8b4365" in s:
            print(a)


def analysic(s):
    from collections import Counter
    s = sorted(Counter(s).items())
    for k, v in s:
        print(f"'{k}'({ord(k)}): {v}")


# jother 8个字符包括： ! + ( ) [ ] { },在浏览器控制台里输入密文即可解密
# aaencode 颜表情
# jjencode $_:![]+""()
# jsfuck []()!+
# jjencode、aaencode、jsfuck解密方式
"""
浏览器控制台输入
Function.prototype.__defineGetter__('constructor', function() {
return function(...args) {
console.log('code:', ...args);
return Function(...args);
};
});
// run code here
"""
__all__ = [Caesar, Vigenere, Affine, RailFence, Morse, Bacon, Rot13, Rot18,
           Rot47, brainfuck, Ascii, Shift, C01248, UrlEncode, Unicode, Hill]

if __name__ == '__main__':
    print(Hill.decrypt([17 ,17 ,5 ,21 ,18 ,21 ,2 ,2 ,19],'ygc'))
    
