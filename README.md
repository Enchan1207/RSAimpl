# RSA

## Overview

RSA暗号の実装

## Implement

### generate key

 1. 2つの素数p, qを生成する．（今回は，13と19）
 2. n = p × q を計算する．
 3. Euler(n) = (p - 1) × (q - 1) を計算する．
 4. Euler(n) と互いに素となる数を求め，e とする．但し，1 < e < Euler(n)
 5. (e × d) mod Euler(n) = 1 となるd を計算する．



