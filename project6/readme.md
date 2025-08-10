
1. **为什么把群元素表示为 scalar\*G（整数）**：

   * 论文在实现时用真实的 EC group 元素（prime256v1）与 exponentiation；但在 Python 的 `cryptography` 中，直接对任意点做“任意 scalar × point”运算或导出点对应的“标量”不太方便。协议的核心在于“对哈希到群的元素进行幂运算并比较是否相等”，用 **等价的抽象：将 H(x) 映射到标量 s（mod n），把群元素表示为 s·G；再次 exponentiate (s·G)^{k} 对应算 s\*k mod n**，在语义上对交集检测和相等比较完全等价（用于演示/验证协议逻辑）。若你要对接 OpenSSL /生产实现，请直接用 curve points 与实际 exponentiation 操作（论文在部署使用 prime256v1）。论文里也建议用 prime256v1 + SHA-256 hashing-to-curve（或重试直到位于曲线上）。

2. **Paillier 与 ARefresh**：

   * 用 `phe` 库做教学 Paillier。论文中采用 Paillier + Damgård–Jurik 和 slotting 以优化通信（节省带宽）。若你需要与论文相同的 ciphertext/slotting 参数，需要用底层 BigNum/OpenSSL 实现并实现 Damgård–Jurik；论文 Appendix B 有参数与讨论。

3. **随机种子（session seed）**：

   * 论文建议 parties 选一个公共随机 seed 并将其 prepend 到每个输入以模拟新 random oracle per execution（避免重复 across runs）。示例中用 `seed=b'session-seed-123'`。

4. **安全模型**：

   * 示例假设双方半诚实（honest-but-curious），协议的安全证明在论文 Appendix D。演示代码没有加入抗重放、防篡改、认证、或抗恶意方的证明——实际部署需要 TLS + authenticated messages + 更强证明。

5. **正确性验证**：

   * 运行脚本会打印：P1 观测到的交集大小（count）与 P2 解密得到的 sum。示例中期望值与解密结果应相符。
