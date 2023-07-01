#
# RSA暗号鍵生成CLI
#

import sys
import argparse
from typing import Optional

from myrsa.keygen import RSAKeyGenerator


def main() -> int:
    """RSA暗号鍵生成CLIの実装

    Returns:
        int: 終了コード
    """

    # コマンドライン引数をパースし、p,qを取り出す
    parser = argparse.ArgumentParser(prog='myrsakeygen', description="RSA encryption key generator")
    parser.add_argument("p", type=int, help="prime number p")
    parser.add_argument("q", type=int, help="prime number q")
    parser.add_argument("--output_file", "-o", help="key output destination")
    args = parser.parse_args()
    p: int = args.p
    q: int = args.q
    dest: Optional[str] = args.output_file

    # 生成器にかける
    try:
        public_key, private_key = RSAKeyGenerator.generate_key(p, q)
    except ValueError as e:
        print(f"Failed to create RSA encrypt keys: {e}")
        return 1

    # nの値を表現するのに必要なバイト数を計算する
    n_bytelen = 1
    key_n = public_key.n
    while key_n > 255:
        n_bytelen += 1
        key_n >>= 8

    # 鍵の持つ値を16進数文字列に変換
    hex2str = lambda x, nbytes: format(x, f"0{nbytes*2}X")
    e_str = hex2str(public_key.e, n_bytelen)
    d_str = hex2str(private_key.d, n_bytelen)
    n_str = hex2str(public_key.n, n_bytelen)

    # 出力先が指定されなかった場合はコンソールに出力して終了
    if dest is None:
        print(f"e=0x{e_str}, d=0x{d_str}, n=0x{n_str}")
        return 0

    # 出力先に書き込む
    try:
        # 秘密鍵ファイル
        with open(dest, "w") as f:
            f.write("\n".join([d_str, n_str]))

        # 公開鍵ファイル (末尾に .pub を追加)
        with open(f"{dest}.pub", "w") as f:
            f.write("\n".join([e_str, n_str]))
    except Exception as e:
        print(f"Failed to export generate keys:{e}")
        return 1

    print("finished.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
