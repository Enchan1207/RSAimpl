#
# RSAデコードCLI
#

import argparse
import sys
from typing import BinaryIO, Optional, TextIO

from ..core import RSAKey
from ..core.decode import RSADecoder


def main() -> int:
    """RSAデコードCLIの実装

    Returns:
        int: 終了コード
    """

    # コマンドライン引数をパース
    parser = argparse.ArgumentParser(prog='myrsadecode', description="RSA decryption")
    parser.add_argument("--key_file", "-k", type=str, required=True, help="RSA key file")
    parser.add_argument("--input_file", "-i", help="output destination of decoded data")
    parser.add_argument("--output_file", "-o", help="output destination of decoded data")
    args = parser.parse_args()

    # 入出力を構成
    try:
        input_source = configure_input_source(args)
        output_source = configure_output_source(args)
    except RuntimeError as e:
        print(f"Failed to configure input/output source: {e}")
        return 1

    # 鍵ファイルから鍵オブジェクトを構成し、エンコーダを初期化
    try:
        key_file_path: str = args.key_file
        if not key_file_path.endswith(".privkey"):
            raise ValueError("file name of public key must ends with .privkey")

        with open(key_file_path) as f:
            private_key = RSAKey.deserialize(f.read())
    except Exception as e:
        print(f"Failed to load RSA key file: {e}")
        return 1

    decoder = RSADecoder(private_key)

    # 入力ソースから読み込み、デコーダに通して出力に書き出す
    with input_source, output_source:
        decoded_data = decoder.decode(input_source.read())

        # デコーダが返すのはASCIIコードの配列なので、 chr() により変換してから出力
        output_source.write("".join([chr(n) for n in decoded_data]))
    return 0


def configure_input_source(args: argparse.Namespace) -> BinaryIO:
    """コマンドライン引数から入力ソースを構成

    Args:
        args (argparse.Namespace): コマンドライン引数

    Returns:
        BinaryIO: 構成された入力ソース。

    Raises:
        RuntimeError: 入力ソースの構成に失敗した場合。

    Note:
        入力は オプション --input_file, 標準入力のいずれかをとります。
        --input_fileが指定されている場合はそれを用い、そうでなければ標準入力から読み込みます。
    """

    try:
        input_file: Optional[str] = args.input_file
    except AttributeError:
        raise RuntimeError("bad command-line argument")

    if input_file is not None:
        try:
            return open(input_file, "rb")
        except Exception:
            raise RuntimeError(f"failed to open specified file: {input_file}")
    else:
        return sys.stdin.buffer


def configure_output_source(args: argparse.Namespace) -> TextIO:
    """コマンドライン引数から出力ソースを構成

    Args:
        args (argparse.Namespace): コマンドライン引数

    Returns:
        TextIO: 構成された出力ソース

    Raises:
        RuntimeError: 出力ソースの構成に失敗した場合。

    Note:
        出力は オプション output_file が指定されている場合はそれを開き使用します。
        オプションが渡されなかった場合は標準出力に書き出されます。
    """

    try:
        output_file: Optional[str] = args.output_file
    except AttributeError:
        raise RuntimeError("bad command-line argument")

    if output_file is None:
        return sys.stdout

    try:
        return open(output_file, "w")
    except Exception:
        raise RuntimeError(f"failed to open specified file: {output_file}")


if __name__ == "__main__":
    sys.exit(main())
