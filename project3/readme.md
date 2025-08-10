
# Poseidon2 (t=3,d=5) — circom + Groth16 实现工程

## 概要
本工程按 Poseidon2 论文与社区实现（jf_poseidon2）生成参数（BN254 域），并实现 circom 电路与 Groth16 证明流程：
- 参数: (n,t,d) = (256, 3, 5)
- 电路公开输入: digest
- 电路私密输入: preimage（单 block，长度 t-1 = 2）
- 证明: Groth16 via snarkjs

参考：
- Poseidon2 论文（参数表 Table1）。  
- jf_poseidon2 crate（用于从社区实现导出 BN254 常数）。:contentReference[oaicite:1]{index=1}

## 文件说明
- `export_constants.rs`：Rust 程序，依赖 `jf_poseidon2`，把 BN254 的 Poseidon2 常数导出为 `constants.json`。  
- `convert_constants_node.js`：把 `constants.json` 转换成 `constants.circom`（供电路 include 使用）。  
- `Poseidon2.circom`：circom 电路（t=3,d=5）。  
- `build.sh`：一键执行流程：`cargo run` -> `node convert_constants_node.js` -> `circom` -> `snarkjs`...  
- `compute_test_vector.js`：演示如何用 `@zkpassport/poseidon2` 在 Node 中计算 digest（用于校验）。


