#
# RSAによる暗号化
#
import functools
from typing import List, Union

from . import RSAKey


class RSAEncoder:
    """RSAエンコーダ
    """

    def __init__(self, public_key: RSAKey) -> None:
        """公開鍵を渡してエンコーダを初期化

        Args:
            public_key (RSAKey): 公開鍵
        """
        self._public_key = public_key

    def encode(self, message: Union[int, List[int], str, bytes]) -> bytes:
        """エンコーダの持つ公開鍵で引数に渡されたオブジェクトを暗号化する

        Args:
            message (Union[int, List[int], str, bytes]): 暗号化するオブジェクト

        Returns:
            bytes: 暗号化結果

        Raises:
            ValueError: 引数に不正な値が渡された場合。

        Note:
            英数字またはそれに対応するASCIIコードの数値以外が入力された場合はValueErrorを送出します。
        """

        # 一律でbytesに変換
        message_bytes: bytes = b''
        try:
            if isinstance(message, int) or isinstance(message, list):
                message_bytes = bytes(message)
            elif isinstance(message, str):
                message_bytes = message.encode("ascii")
            else:
                message_bytes = message
        except Exception:
            raise ValueError("Invalid argument")

        return self._encode(message_bytes)

    def _encode(self, data: bytes) -> bytes:
        """暗号化処理の実体

        Args:
            data (bytes): 暗号化するバイナリオブジェクト

        Returns:
            bytes: 暗号化結果

        Raises:
            ValueError: 引数dataに英数字以外が含まれている場合
        """

        # 不正値チェック
        if not data.isalnum():
            raise ValueError("Invalid argument")

        # dataの各データごと x^e mod n を計算し、一旦リストに起こす
        encoded_data = [pow(x, self._public_key.exponent, self._public_key.modulo) for x in data]

        # 暗号化されたデータのビット長は、入力ではなく鍵のモジュロnによって決定される
        # したがって、鍵によっては1データが2byte以上の値に変換される可能性がある
        # しかしbytesのイニシャライザは256以上の値を受け付けないため、
        # int.to_bytesを用いてひとつずつbytesにしていく

        # nの値を表現するのに必要なバイト数を計算する
        nbytes_modulo = 1
        key_n = self._public_key.modulo
        while key_n > 255:
            nbytes_modulo += 1
            key_n >>= 8

        # to_bytesで変換し、reduceで結合して返す
        encoded_byte_list = [n.to_bytes(nbytes_modulo, byteorder="little") for n in encoded_data]
        encoded_bytes = functools.reduce(lambda x, y: x + y, encoded_byte_list)
        return encoded_bytes
