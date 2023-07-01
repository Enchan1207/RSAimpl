#
# RSA暗号モジュール コア
#

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class RSAKey:
    """RSA鍵
    """
    modulo: int
    exponent: int

    def __str__(self) -> str:
        """簡素な文字列表現を返す
        """
        return f"modulo:{hex(self.modulo)} exponent:{hex(self.exponent)}"

    def serialize(self) -> str:
        """鍵をシリアライズする

        Returns:
            str: シリアライズされた鍵オブジェクト
        """

        # nの値を表現するのに必要なバイト数を計算
        n_bytelen = 1
        key_n = self.modulo
        while key_n > 255:
            n_bytelen += 1
            key_n >>= 8

        # 双方の値の桁数を合わせる
        hex2str = lambda x, nbytes: format(x, f"0{nbytes*2}X")
        n_str = hex2str(self.modulo, n_bytelen)
        e_str = hex2str(self.exponent, n_bytelen)
        return "\n".join([n_str, e_str])

    @staticmethod
    def deserialize(serialized: str) -> RSAKey:
        """文字列から鍵オブジェクトを生成する

        Args:
            serialized (str): シリアライズされた鍵

        Returns:
            PublicKey: 生成された鍵オブジェクト

        Raises:
            ValueError: デシリアライズに失敗した場合
        """

        # 文字列を改行でパース
        n_str, e_str = tuple(serialized.split("\n"))

        # 数値に変換
        n_int = int(n_str, 16)
        e_int = int(e_str, 16)
        return RSAKey(n_int, e_int)
