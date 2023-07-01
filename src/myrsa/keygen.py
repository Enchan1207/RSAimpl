#
# 暗号鍵の生成
#

import functools
import math
import random
from typing import Callable, Tuple

from . import PrivateKey, PublicKey


class RSAKeyGenerator:

    @staticmethod
    def generate_key(p: int, q: int) -> Tuple[PublicKey, PrivateKey]:
        """2つの素数p, qからRSA暗号鍵のペアを生成する

        Args:
            p (int): 素数1
            q (int): 素数2

        Returns:
            Tuple[RSAPublicKey, RSAPrivateKey]: 生成されたRSA暗号鍵

        Raises:
            ValueError: 入力のいずれかが素数でない場合
        """

        # p, qが素数であることを確認
        if not RSAKeyGenerator._is_prime(p) or not RSAKeyGenerator._is_prime(q):
            raise ValueError(f"p and q must be prime (passed: p={p}, q={q})")

        # n, Euler(n) を計算
        n: int = p * q
        euler_n: int = (p - 1) * (q - 1)

        # 2 ~ Euler(n)-1 の範囲でeの候補を絞る (条件: xとEuler(n) が互いに素)
        e_candidates = list(filter(lambda x: math.gcd(x, euler_n) == 1, range(2, euler_n)))

        # eからdを計算する
        # axとbがnを法として合同であるとき、これを満たす解xの個数はd=(a,n)=1 つまり一意に定まる
        # ただし、eの値の取り方によっては e == d となってしまう場合があるため、
        # e != d となるまで繰り返す処理を入れている
        e: int = random.choice(e_candidates)
        d: int = e
        while e == d:
            # eを選び直す
            e = random.choice(e_candidates)

            # 入力xがeに対するdとして適切かどうか計算する関数
            d_cond_func: Callable[[int, int], bool] = lambda x, e: (x * e) % euler_n == 1

            # 関数を 2~Euler(n) の範囲に適用し、最初の要素を抜き出してdとする
            d_candidates = list(filter(functools.partial(d_cond_func, e=e), range(2, euler_n)))
            d = d_candidates[0]

        # 完了 生成できた n, e, d の値をもとに鍵オブジェクトを作成して返す
        return (PublicKey(n, d), PrivateKey(n, e))

    @staticmethod
    def _is_prime(x: int) -> bool:
        """ある数値が素数かどうか判定する

        Args:
            x (int): 判定する値

        Returns:
            bool: 判定結果
        """

        # 素数とは、1とその数以外で割り切れない数
        # つまり、nに対して 2~n の範囲においてGCDを計算し、すべて1ならばその数は素数
        # ただし、n = a * b の関係が成立するとき n = b * a も同時になり立つため、
        # 計算する範囲は 2~√n でよい

        # √xを下回る最大の整数を求め、2からその数までのrangeオブジェクトをつくる
        # floorではなくceilを使っているのは、rangeが第2引数-1までの値を返すため
        prime_check_range = range(2, math.ceil(math.sqrt(x)))

        # それぞれについてGCDを計算
        for n in prime_check_range:
            if RSAKeyGenerator._euclid_gcd(x, n) != 1:
                return False

        return True

    @staticmethod
    def _euclid_gcd(x: int, y: int) -> int:
        """ユークリッドの互除法により最大公約数を計算する

        Args:
            x (int): 入力1
            y (int): 入力2

        Returns:
            int: 最大公約数
        """
        # xと0とのGCDは常にx
        if x == 0 or y == 0:
            return y if x == 0 else x

        # 初期状態を設定
        r: int = y
        r_prev: int = x

        while r != 0:
            # 剰余を計算
            r_next: int = r_prev % r

            # 被除数は前のループの除数
            r_prev = r

            # 計算した剰余を次のループの除数とする
            r = r_next

        # r=0のとき、その前のrの値が GCD(x, y)
        return r_prev
