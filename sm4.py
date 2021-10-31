#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File          : sm4.py
@Description   : sm4加密算法的实现
@Date          : 2021/10/28 15:59:51
@Author        : ZelKnow
@Github        : https://github.com/ZelKnow
"""
__author__ = "ZelKnow"

from argparse import ArgumentParser, ArgumentError
from binascii import hexlify, unhexlify
from utils import S_BOX, BLOCK_BYTE, FK, CK, BLOCK_HEX
from utils import rotl, num2hex, bytes_to_list, list_to_bytes, padding, unpadding

ENCRYPT = 0  # 加密
DECRYPT = 1  # 解密


class CryptSM4(object):
    def __init__(self):
        self.rk = []

    def T(self, A, L_func):
        """合成置换函数T
        T(.) = L(\tau(.))

        Args:
            A (int): 输入数据
            L_func (function): 线性变换L

        Returns:
            int: 输出数据
        """
        B = [S_BOX[(A >> i) & (0x000000ff)] for i in range(0, 32, 8)]
        B = [B[i] << (i * 8) for i in range(4)]
        C = L_func(sum(B))
        return C

    def L(self, input):
        """线性变换L，用于轮函数中
        L(B) = B ^ (B <<< 2) ^ (B <<< 10) ^ (B <<< 18) ^ (B <<< 24)

        Args:
            input (int): 输入数据

        Returns:
            int: 输出数据
        """
        return input ^ rotl(input, 2) ^ rotl(input, 10) ^ rotl(
            input, 18) ^ rotl(input, 24)

    def L_prime(self, input):
        """线性变换L'，用于密钥扩展算法
        L'(B) = B ^ (B <<< 13) ^ (B <<< 23)

        Args:
            input (int): 输入数据

        Returns:
            int: 输出数据
        """
        return input ^ rotl(input, 13) ^ rotl(input, 23)

    def check_key_iv(self, key_iv):
        """检验key或iv的合法性并转换成字节串

        Args:
            key_iv (int, str or bytes): key或iv

        Raises:
            TypeError: 密钥或初始化向量类型错误
            ValueError: 密钥或初始化向量长度过长

        Returns:
            bytes: key或iv
        """
        if isinstance(key_iv, str):
            key_iv = key_iv.encode(encoding='UTF8')
        elif isinstance(key_iv, int):
            print(len(num2hex(key_iv, width=32)))
            key_iv = unhexlify(num2hex(key_iv, width=32))
        elif not isinstance(key_iv, bytes):
            raise TypeError("密钥或初始化向量类型错误")
        if len(key_iv) > BLOCK_BYTE:
            raise ValueError('密钥或初始化向量长度不能大于{}'.format(BLOCK_BYTE))
        return unhexlify('00') * (BLOCK_BYTE - len(key_iv)) + key_iv

    def set_key(self, key):
        """设置key

        Args:
            key (int, str or bytes): 密钥
        """
        key = self.check_key_iv(key)
        input = bytes_to_list(hexlify(key), BLOCK_HEX / 4)
        input = [int(i, 16) for i in input]
        K = [input[i] ^ FK[i] for i in range(4)]  # 存储轮密钥
        for i in range(32):  # 密钥扩展算法
            K.append(K[i] ^ self.T(K[i + 1] ^ K[i + 2] ^ K[i + 3]
                                   ^ CK[i], self.L_prime))
        self.rk = K[4:]

    def F(self, X, i):
        """轮函数F
        F = X_0 ^ T(X_1 ^ X_2 ^ X_3 ^ rk)
        其中输入为(X_0, X_1, X_2, X_3)，轮密钥为rk

        Args:
            X (list): 输入
            i (int): 轮密钥的下标

        Returns:
            int: 输出
        """
        return X[0] ^ self.T(X[1] ^ X[2] ^ X[3] ^ self.rk[i], self.L)

    def _crypt(self, x, mode=ENCRYPT):
        """加解密函数

        Args:
            x (int): 需加解密的数据
            mode (int, optional): 加密或解密. Defaults to ENCRYPT.

        Returns:
            int: 输出
        """
        input = [(x >> i) & (0xffffffff) for i in reversed(range(0, 128, 32))]
        # 加解密时使用的轮密钥顺序不同
        for i in range(32) if mode == ENCRYPT else reversed(range(32)):
            input.append(self.F(input[-4:], i))  # 32次迭代运算
        output = input[-4:]
        output = [output[i] << (i * 32) for i in range(4)]  # 反序变换
        return sum(output)

    def encrypt(self, x):
        """加密函数

        Args:
            x (int): 需加密的数据

        Returns:
            int: 输出
        """
        return self._crypt(x, ENCRYPT)

    def decrypt(self, x):
        """解密函数

        Args:
            x (int): 需解密的数据

        Returns:
            int: 输出
        """
        return self._crypt(x, DECRYPT)

    def _crypt_ECB(self, input, mode=ENCRYPT):
        """ECB加解密函数

        Args:
            x (int): 需加解密的数据
            mode (int, optional): 加密或解密. Defaults to ENCRYPT.

        Returns:
            int: 输出
        """
        input_list = bytes_to_list(input, BLOCK_BYTE)  # 将输入拆分成block
        input_list = [int(hexlify(i), 16) for i in input_list]
        output_list = [self._crypt(x, mode) for x in input_list]  # 分别加解密
        output_list = [
            unhexlify(num2hex(o, width=BLOCK_HEX)) for o in output_list
        ]  # 转成字节流
        return list_to_bytes(output_list)  # 合并

    def encrypt_ECB(self, plain_text):
        """ECB加密函数

        Args:
            x (int): 需加密的数据

        Returns:
            int: 输出
        """
        return self._crypt_ECB(padding(plain_text), ENCRYPT)

    def decrypt_ECB(self, cipher_text):
        """ECB解密函数

        Args:
            x (int): 需解密的数据

        Returns:
            int: 输出
        """
        try:
            cipher_text = unhexlify(cipher_text)
        except:
            pass
        return unpadding(self._crypt_ECB(cipher_text, DECRYPT))

    def _crypt_CBC(self, input, iv, mode=ENCRYPT):
        """CBC加解密函数

        Args:
            x (int): 需加解密的数据
            mode (int, optional): 加密或解密. Defaults to ENCRYPT.

        Returns:
            int: 输出
        """
        iv = int(hexlify(self.check_key_iv(iv)), 16)  # 初始化向量

        input_list = bytes_to_list(input, BLOCK_BYTE)  # 拆分成block
        input_list = [int(hexlify(i), 16) for i in input_list]
        output_list = []
        for x in input_list:
            if mode == ENCRYPT:
                output_list.append(self._crypt(x ^ iv, mode))
                iv = output_list[-1]
            else:
                output_list.append(self._crypt(x, mode) ^ iv)
                iv = x
        output_list = [
            unhexlify(num2hex(o, width=BLOCK_HEX)) for o in output_list
        ]
        return list_to_bytes(output_list)

    def encrypt_CBC(self, plain_text, iv):
        """CBC加密函数

        Args:
            x (int): 需加密的数据

        Returns:
            int: 输出
        """
        return self._crypt_CBC(padding(plain_text), iv, ENCRYPT)

    def decrypt_CBC(self, cipher_text, iv):
        """CBC解密函数

        Args:
            x (int): 需解密的数据

        Returns:
            int: 输出
        """
        return unpadding(self._crypt_CBC(cipher_text, iv, DECRYPT))


if __name__ == '__main__':
    parser = ArgumentParser(description="SM4加解密")
    parser.add_argument('crypt', choices=['encrypt', 'decrypt'], help='加密或解密')
    parser.add_argument('mode', choices=['ecb', 'cbc'], help='加密模式')
    parser.add_argument('source', help='加密/解密目标')
    parser.add_argument('key', help='密钥')
    parser.add_argument('--iv', help='初始化向量，cbc模式使用')
    parser.add_argument('--source_type',
                        choices=['input', 'bin_file', 'image'],
                        help='加密目标类型',
                        default='input')
    parser.add_argument('--output', help='输出文件名，如不指定则输出至标准输出流')
    args = parser.parse_args()
    c = CryptSM4()
    c.set_key(args.key)

    if args.mode == 'cbc' and args.iv is None:
        raise ArgumentError("请输入初始化向量的值")

    if args.source_type == 'input':
        input = args.source
    elif args.source_type == 'bin_file':
        with open(args.source, 'rb') as f:
            input = f.read()
    else:
        from PIL import Image
        import numpy as np
        source = Image.open(args.source)
        img = np.array(source.convert('RGBA'))
        shape = img.shape
        size = img.size
        input = unhexlify(''.join([num2hex(i, width=2)
                                   for i in img.flatten()]))

    if args.crypt == 'encrypt':
        output = c.encrypt_ECB(input) if args.mode == 'ecb' else c.encrypt_CBC(
            input, args.iv)
    else:
        output = c.decrypt_ECB(input) if args.mode == 'ecb' else c.decrypt_CBC(
            input, args.iv)

    if args.source_type == 'image':
        output = hexlify(output).decode()
        output = output[:size * 2]
        output = [[int(output[i + j:i + j + 2], 16) for j in range(0, 8, 2)]
                  for i in range(0, len(output), 8)]
        output = np.array(output)
        output = Image.fromarray(output.reshape(shape).astype('uint8'))
        output.save(args.output)
    elif args.output:
        with open(args.output, "wb") as f:
            f.write(output)
    else:
        try:
            print(output.decode())
        except:
            print(hexlify(output).decode())
