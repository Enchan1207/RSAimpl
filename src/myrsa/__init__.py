#
# RSA暗号モジュール
#

import dataclasses


@dataclasses.dataclass(frozen=True)
class PublicKey:
    """RSA公開鍵 (暗号鍵)
    """
    n: int
    e: int


@dataclasses.dataclass(frozen=True)
class PrivateKey:
    """RSA秘密鍵 (復号鍵)
    """
    n: int
    d: int
