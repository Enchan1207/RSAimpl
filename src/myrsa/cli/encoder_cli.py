#
# RSAエンコードCLI
#

import argparse
import io
import sys
from typing import BinaryIO, List, Optional, TextIO

from ..core import RSAKey
from ..core.encode import RSAEncoder


def main() -> int:
    """RSAエンコードCLIの実装

    Returns:
        int: 終了コード
    """

    # コマンドライン引数をパース
    parser = argparse.ArgumentParser(prog='myrsaencode', description="RSA encryption")
    parser.add_argument("--key_file", "-k", type=str, required=True, help="RSA key file")
    parser.add_argument("--input_file", "-i", help="output destination of decoded data")
    parser.add_argument("--output_file", "-o", help="output destination of decoded data")
    parser.add_argument("data", type=str, nargs="*", help="data to encode")
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
        if not key_file_path.endswith(".pubkey"):
            raise ValueError("file name of public key must ends with .pubkey")

        with open(key_file_path) as f:
            public_key = RSAKey.deserialize(f.read())
    except Exception as e:
        print(f"Failed to load RSA key file: {e}")
        return 1

    encoder = RSAEncoder(public_key)

    # 入力ソースから読み込み、エンコーダに通して出力に書き出す
    with input_source, output_source:
        # 改行を削除
        input_data = input_source.read().replace("\r", "").replace("\n", "")
        output_source.write(encoder.encode(input_data))

    return 0


def configure_input_source(args: argparse.Namespace) -> TextIO:
    """コマンドライン引数から入力ソースを構成

    Args:
        args (argparse.Namespace): コマンドライン引数

    Returns:
        TextIO: 構成された入力ソース。

    Raises:
        RuntimeError: 入力ソースの構成に失敗した場合。

    Note:
        入力は 実行引数data, オプション --input_file, 標準入力の3種類をとります。
        dataと--input_fileのいずれかが指定されている場合はそれらを用い、
        どちらも指定がなければ標準入力から読み込みます。
        これらを同時に指定した場合は例外が送出されます。
    """

    try:
        data: List[str] = args.data
        input_file: Optional[str] = args.input_file
    except AttributeError:
        raise RuntimeError("bad command-line argument")

    if len(data) > 0 and input_file is not None:
        raise RuntimeError("cannot specify both argument data and option input_file")

    if len(data) > 0:
        return io.StringIO(" ".join(data))
    elif input_file is not None:
        try:
            return open(input_file)
        except Exception:
            raise RuntimeError(f"failed to open specified file: {input_file}")
    else:
        return sys.stdin


def configure_output_source(args: argparse.Namespace) -> BinaryIO:
    """コマンドライン引数から出力ソースを構成

    Args:
        args (argparse.Namespace): コマンドライン引数

    Returns:
        TextIO: 構成された出力ソース

    Raises:
        RuntimeError: 出力ソースの構成に失敗した場合。

    Note:
        出力は オプション output_file が指定されている場合はバイナリモードで開き、それを使用します。
        オプションが渡されなかった場合は標準出力に書き出されます。
    """

    try:
        output_file: Optional[str] = args.output_file
    except AttributeError:
        raise RuntimeError("bad command-line argument")

    if output_file is None:
        return sys.stdout.buffer

    try:
        return open(output_file, "wb")
    except Exception:
        raise RuntimeError(f"failed to open specified file: {output_file}")


if __name__ == "__main__":
    sys.exit(main())
