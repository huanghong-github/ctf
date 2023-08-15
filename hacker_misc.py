import base64


def base64_solve_stego(baselist):
    """
    base64隐写
    :param baselist: base64列表
    :return:
    """

    def goflag(bin_str):
        res_str = ''
        for i in range(0, len(bin_str), 8):
            res_str += chr(int(bin_str[i:i + 8], 2))
        return res_str

    def get_base64_diff_value(s1, s2):
        base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        res = 0
        for i in range(len(s2)):
            if s1[i] != s2[i]:
                return abs(base64chars.index(s1[i]) - base64chars.index(s2[i]))
        return res

    bin_str = ''
    for line in baselist:
        steg_line = line.replace('\n', '')
        norm_line = base64.b64encode(base64.b64decode(steg_line.encode())).decode().replace('\n', '')
        diff = get_base64_diff_value(steg_line, norm_line)
        print(diff)
        pads_num = steg_line.count('=')
        if diff:
            bin_str += bin(diff)[2:].zfill(pads_num * 2)
        else:
            bin_str += '0' * pads_num * 2
        print(goflag(bin_str))


if __name__ == '__main__':
    with open(path) as f:
        base64_solve_stego(f.readlines())
    pass
