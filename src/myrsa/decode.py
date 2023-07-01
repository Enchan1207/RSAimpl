#
# RSAによる復号
#
import functools
from typing import Callable

from . import PrivateKey


class RSADecoder:
    """RSAデコーダ
    """

    def __init__(self, private_key: PrivateKey) -> None:
        """秘密鍵を渡してデコーダを初期化

        Args:
            public_key (PrivateKey): 秘密鍵
        """
        self._private_key = private_key

    def decode(self, encoded_data: bytes) -> bytes:
        """エンコーダの持つ秘密鍵で引数に渡されたオブジェクトを復号する

        Args:
            encoded_data (bytes): 復号するバイナリオブジェクト

        Returns:
            bytes: 復号結果

        Raises:
            ValueError: 引数に不正な値が渡された場合。
        """

        # 鍵のモジュロから1データあたりのバイト数を取得
        nbytes_modulo = 1
        key_n = self._private_key.n
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
        decoded_data = [pow(x, self._private_key.d, self._private_key.n) for x in encoded_data_chunks]

        # 長さnbytes_moduloのbytesに変換して返す
        decoded_byte_list = [n.to_bytes(nbytes_modulo, byteorder="little") for n in decoded_data]
        decoded_bytes = functools.reduce(lambda x, y: x + y, decoded_byte_list)
        return decoded_bytes
