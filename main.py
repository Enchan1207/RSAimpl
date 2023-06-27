#
#
#
import math
import sys
from typing import Callable, List, Tuple
import dataclasses
import random
import functools
from bytes_split import splitbytes, concatbytes


@dataclasses.dataclass
class RSAPublicKey:
    """RSA公開鍵 (暗号鍵)
    """
    n: int
    e: int


@dataclasses.dataclass
class RSAPrivateKey:
    """RSA秘密鍵 (復号鍵)
    """
    n: int
    d: int


def main() -> int:

    p: int = 13
    q: int = 19
    pub_key, priv_key = generate_key(p, q)

    print(pub_key)
    print(priv_key)

    data = list(range(pub_key.n))
    encrypted_data = encode(data, pub_key)
    decrypted_data = decode(encrypted_data, priv_key)

    for d1, d2 in zip(data, decrypted_data):
        assert d1 == d2

    encrypted = encrypt(0xFFFFFFFF.to_bytes(length=4, byteorder="little"), pub_key)
    decrypted = decrypt(encrypted, priv_key)
    print(encrypted.hex(" "))
    print(decrypted.hex(" "))

    return 0


def encrypt(data: bytes, key: RSAPublicKey) -> bytes:
    """暗号化

    Args:
        data (bytes): 暗号化する値
        key (RSAPublicKey): 鍵

    Returns:
        bytes: 暗号化されたデータ
    """

    # 暗号鍵で表現可能な値(key.n)が256を上回る場合はそのまま通す
    if key.n >= 256:
        encode: Callable[[int], bytes] = lambda x: pow(x, key.e, key.n).to_bytes(length=1, byteorder="little")
        encoded_data: bytes = functools.reduce(lambda x, y: x + y, map(encode, data))
        return encoded_data

    # key.nを下回る最大の2の冪数を探す
    asserted_msb = lambda x: len(f"{x:b}") - 1 - f"{x:b}".find("1")
    available_bit_length = asserted_msb(key.n)

    # 入力のバイト列を available_bit_length ビットずつに分割して暗号化
    splitted_data: List[int] = list(splitbytes(data, available_bit_length))
    result = list(map(lambda x: pow(x, key.e, key.n), splitted_data))

    # バイナリに変換
    to_bin = functools.partial(int.to_bytes, length=1, byteorder="little")
    return functools.reduce(lambda x, y: x + y, map(to_bin, result))


def decrypt(data: bytes, key: RSAPrivateKey) -> bytes:
    """復号化

    Args:
        data (bytes): 復号化する値
        key (RSAPrivateKey): 鍵

    Returns:
        bytes: 復号化されたデータ
    """
    # 暗号鍵で表現可能な値(key.n)が256を上回る場合はそのまま通す
    if key.n >= 256:
        decode: Callable[[int], bytes] = lambda x: pow(x, key.d, key.n).to_bytes(length=1, byteorder="little")
        decoded_data: bytes = functools.reduce(lambda x, y: x + y, map(decode, data))
        return decoded_data

    # key.nを下回る最大の2の冪数を探す
    asserted_msb = lambda x: len(f"{x:b}") - 1 - f"{x:b}".find("1")
    available_bit_length = asserted_msb(key.n)

    # 入力のバイト列を available_bit_length ビットで分割されたものと解釈し、結合 復号化する
    concatinated_data: List[int] = list(concatbytes(data, available_bit_length))
    result = list(map(lambda x: pow(x, key.d, key.n), concatinated_data))

    # バイナリに変換
    to_bin = functools.partial(int.to_bytes, length=1, byteorder="little")
    return functools.reduce(lambda x, y: x + y, map(to_bin, result))


def encode(data: List[int], key: RSAPublicKey) -> List[int]:
    """暗号鍵を用いて値を暗号化する

    Args:
        data (List[int]): 暗号化する値
        key (RSAPublicKey): 鍵

    Returns:
        List[int]: 結果
    """
    return list(map(lambda x: pow(x, key.e, key.n), data))


def decode(data: List[int], key: RSAPrivateKey) -> List[int]:
    """復号鍵を用いて値を復号化する

    Args:
        data (List[int]): 復号化する値
        key (RSAPublicKey): 鍵

    Returns:
        List[int]: 結果
    """
    return list(map(lambda x: pow(x, key.d, key.n), data))


def generate_key(p: int, q: int) -> Tuple[RSAPublicKey, RSAPrivateKey]:
    """2つの素数p, qからRSA暗号鍵のペアを生成する

    Args:
        p (int): 素数1
        q (int): 素数2

    Returns:
        Tuple[RSAPublicKey, RSAPrivateKey]: 生成されたRSA暗号鍵
    """

    n: int = p * q
    euler_n: int = (p - 1) * (q - 1)

    # 2 ~ Euler(n)-1 の範囲でeの候補を絞る (条件: xとEuler(n) が互いに素)
    e_candidates = list(filter(lambda x: math.gcd(x, euler_n) == 1, range(2, euler_n)))
    e = random.choice(e_candidates)

    # axとbがnを法として合同であるとき、これを満たす解xの個数はd=(a,n)=1
    # よってdは一意に定まる
    d_candidates = list(filter(lambda d: (e * d) % euler_n == 1, range(2, euler_n)))
    d = d_candidates[0]

    return (RSAPublicKey(n, d), RSAPrivateKey(n, e))


if __name__ == "__main__":
    sys.exit(main())
