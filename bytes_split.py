#
# bytes型を任意bitで分割・結合する
#

import functools
from typing import List


def splitbytes(data: bytes, n_sep: int) -> bytes:
    """bytes型のデータを任意のビット数ごとに分割する

    Args:
        data (bytes): データ
        n_sep (int): 分割ビット数

    Returns:
        bytes: 処理結果

    Raises:
        ValueError: 分割数に不正な値が渡された場合
    """
    if n_sep < 1 or n_sep > 7:
        raise ValueError("Invalid argument")

    # 結果
    result: List[int] = []

    # 未処理のデータ
    untreated_bits: List[int] = []

    bin2int = lambda int_list: int("".join(map(str, int_list)), 2)

    for byte in data:
        # 1byteをビットごとに分割
        splitted_byte = list(map(int, list(f"{byte:08b}")))

        # 未処理のデータ配列と合わせてn_sep個になるように取り出し、結果に追加
        left = n_sep - len(untreated_bits)
        result.append(bin2int(untreated_bits + splitted_byte[:left]))
        untreated_bits = []

        # 残ったデータを追加する
        untreated_bits += splitted_byte[left:]

        # 処理できる分は流す
        while len(untreated_bits) >= n_sep:
            result.append(bin2int(untreated_bits[:n_sep]))
            untreated_bits = untreated_bits[n_sep:]

    if len(untreated_bits) > 0:
        # n_sepビットになるまで左にずらす
        result.append(bin2int(untreated_bits + ([0] * (n_sep - len(untreated_bits)))))

    # 結合
    to_bin = functools.partial(int.to_bytes, length=1, byteorder="little")
    return functools.reduce(lambda x, y: x + y, map(to_bin, result))


def concatbytes(data: bytes, n_sep: int) -> bytes:
    """あるビット数ごとに分割されたバイト列を8bitに戻す

    Args:
        data (bytes): データ
        n_sep (int): 分割数

    Returns:
        bytes: 変換結果

    Raises:
        ValueError: 分割数に不正な値が渡された場合
    """
    if n_sep < 1 or n_sep > 7:
        raise ValueError("Invalid argument")

    untreated: str = ""

    result: List[int] = []

    for byte in data:
        # 下位n_sepビット取り出す
        byte_str = f"{byte:08b}"[(8 - n_sep):]

        # バッファに追加
        untreated += byte_str
        while len(untreated) >= 8:
            result.append(int(untreated[:8], 2))
            untreated = untreated[8:]

    # 結合
    to_bin = functools.partial(int.to_bytes, length=1, byteorder="little")
    return functools.reduce(lambda x, y: x + y, map(to_bin, result))
