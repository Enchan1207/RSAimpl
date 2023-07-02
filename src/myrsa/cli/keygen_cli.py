#
# RSA暗号鍵生成CLI
#

import sys
import argparse
from typing import Optional

from ..core.keygen import RSAKeyGenerator


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

    # 生成結果を表示
    print(f"public key: {public_key}")
    print(f"private key: {private_key}")

    # 出力先が指定されなかった場合はコンソールに出力して終了
    if dest is None:
        return 0

    # 出力先に書き込む
    try:
        # 秘密鍵ファイル (末尾に .privkey を追加)
        with open(f"{dest}.privkey", "w") as f:
            f.write(private_key.serialize())

        # 公開鍵ファイル (末尾に .pubkey を追加)
        with open(f"{dest}.pubkey", "w") as f:
            f.write(public_key.serialize())
    except Exception as e:
        print(f"Failed to export generate keys:{e}")
        return 1

    print("finished.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
