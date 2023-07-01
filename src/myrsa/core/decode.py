#
# RSAによる復号
#
import functools
from typing import Callable, List

from . import RSAKey


class RSADecoder:
    """RSAデコーダ
    """

    def __init__(self, private_key: RSAKey) -> None:
        """秘密鍵を渡してデコーダを初期化

        Args:
            public_key (RSAKey): 秘密鍵
        """
        self._private_key = private_key

    def decode(self, encoded_data: bytes) -> List[int]:
        """エンコーダの持つ秘密鍵で引数に渡されたオブジェクトを復号する

        Args:
            encoded_data (bytes): 復号するバイナリオブジェクト

        Returns:
            List[int]: 復号結果

        Raises:
            ValueError: 引数に不正な値が渡された場合。
        """

        # 鍵のモジュロから1データあたりのバイト数を取得
        nbytes_modulo = 1
        key_n = self._private_key.modulo
        while key_n > 255:
            nbytes_modulo += 1
            key_n >>= 8

        # 暗号文の長さはnbytes_moduloの倍数であるはず
        if len(encoded_data) % nbytes_modulo != 0:
            raise ValueError("Invalid data length")

        # データをnbytes_moduloバイトごとに分割し、intに戻す
        byte2int: Callable[[bytes], int] = functools.partial(int.from_bytes, byteorder="little")
        encoded_data_chunks = [byte2int(encoded_data[n:n + nbytes_modulo]) for n in range(0, len(encoded_data), nbytes_modulo)]

        # 各データについて x^d mod n を計算する
        decoded_data = [pow(x, self._private_key.exponent, self._private_key.modulo) for x in encoded_data_chunks]
        return decoded_data
