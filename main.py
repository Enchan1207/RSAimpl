#
#
#
import math
import sys
from typing import List, Tuple
import dataclasses
import random


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

    data = [random.randint(0, 128) for _ in range(100000)]
    encrypted_data = encode(data, pub_key)
    decrypted_data = decode(encrypted_data, priv_key)

    for d1, d2 in zip(data, decrypted_data):
        assert d1 == d2

    return 0


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
        Tuple[int, int, int]: 生成されたRSA暗号鍵
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
