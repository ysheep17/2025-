### 1. SM3 的正确性要点

* SM3 的压缩函数非常接近 SHA-256 的结构，但细节不同：轮常数 `T_j` 与非线性函数 `FF`/`GG` 的定义在不同轮段不同。上面实现严格按标准写出：

  * `T_j = 0x79cc4519` 对于 j=0..15；`T_j = 0x7a879d8a` 对于 j=16..63。
  * `FF`: j ≤ 15 -> XOR; else -> majority-like `(x&y)|(x&z)|(y&z)`.
  * `GG`: j ≤ 15 -> XOR; else -> `(x&y)|((~x)&z)`.
  * `P0` 与 `P1` 的置换也如规范：`P0(x) = x ⊕ (x <<< 9) ⊕ (x <<< 17)`，`P1(x) = x ⊕ (x <<< 15) ⊕ (x <<< 23)`。
* 所有中间计算都用 `& 0xFFFFFFFF` 保证 32 位环，避免 Python 无限精度干扰。
* padding：按照 SM3，要在消息后追加 `0x80`、若干 `0x00`，再追加 64-bit 大端长度（bits）。


### 2. 优化点

* 避免频繁访问 `self._V`（把其复制到局部变量 A,B,C...，循环结束后再回写）可以显著节省属性访问开销（见 `SM3Optimized`）。
* 使用 `struct.unpack('>16I', block)` 直接得到 16 个 32-bit 大端整数，避免自己逐字节解析。
* 避免重复创建 `bytes` / `bytearray` 对象；将数据缓冲区设为 `bytearray` 并就地切片可减少 GC。
* 尽量把轮常数表 `T_j` 放成模块/类常量，避免每次重构。

### 3. length-extension 攻击实现细节

* 长度扩展攻击基于 Merkle–Damgård 构造：已知 `H(m)` 与 `len(m)`，攻击者可以恢复压缩函数内部状态（因为 `H(m)` 是 state 的编码），然后对 `m || padding(m) || extra` 的后续分组继续压缩，得到 `H(m || padding || extra)`。
* 我们通过 `sm3_state_from_digest()` 将 digest 转成 8 个 32-bit 字（big-endian），把它写入新的 `SM3Optimized` 实例的 `_V`，并把 `_count` 设为 `len(m)+len(padding)`（即已经处理的字节数），然后 `update(extra)` 即可。
* 注意：攻击者需知道 `len(m)`（字节），否则必须猜测（有时能通过 message 格式范围暴力尝试）。示例中的 `demo_length_extension()` 给出验证。
