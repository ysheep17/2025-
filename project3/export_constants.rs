// src/main.rs
use serde::Serialize;
use serde_json::json;
use std::fs::File;
use std::io::Write;

// 下面的模块名请根据实际 crate 名称与路径调整
// 假设 crate 名为 `jf_poseidon2` 且 constants 在 jf_poseidon2::constants::bn254
// 可能需要在 Cargo.toml 里指定正确的 crate 名称
use jf_poseidon2::constants::bn254::{
    RC3_EXT, RC3_INT, MAT_DIAG3_M_1, // 这些名字依据 crate 实现，可能需要调整
};

#[derive(Serialize)]
struct Params {
    t: usize,
    d: usize,
    fullRounds: usize,
    partialRounds: usize,
    mds: Vec<Vec<String>>,
    roundConstants: Vec<Vec<String>>,
}

fn fp_to_str<F: ff::PrimeField>(f: &F) -> String {
    // 将 field element 转成十六进制字符串（以方便 circom 读取）
    // 这里假设元素能用 to_repr() 获得大端字节数组
    let repr = f.into_repr();
    let mut v = vec![];
    repr.write_be(&mut v).unwrap();
    // 转为 0x... hex
    format!("0x{}", hex::encode(v))
}

fn main() {
    // 下面示例基于 t=3 的常数命名（RC3_EXT, RC3_INT, MAT_DIAG3_M_1）
    let t = 3usize;
    let d = 5usize;
    // fullRounds & partialRounds 在 crate 中以常量形式存在或可从数组长度推断
    let mut mds: Vec<Vec<String>> = Vec::new();
    // MAT_DIAG3_M_1 可能是稀疏表示的一部分；为简单起见，我们将构造完整 MDS：
    // 这里示例化：若 crate 没有直接完整 MDS，请根据 crate 文档提取
    // =============================
    // 注意：下面的数据提取方法需要根据实际 crate 的数据结构调整。
    // =============================

    // For demo / template - actual implementation must inspect crate's public consts
    // Example: MAT_DIAG3_M_1 might be composed of diag and m_1 parts; compute full MDS here.
    // For brevity in template, we'll fill with placeholders; actual code should compute/collect constants.

    // Placeholder: fill with zeros (用户运行时请替换上面引用常数提取逻辑)
    for _ in 0..t {
        mds.push(vec!["0x0".to_string(); t]);
    }

    // Combine RC3_EXT and RC3_INT into roundConstants
    // RC3_EXT length = ext rounds (e.g., 8) ; RC3_INT length = int rounds (e.g., 56)
    let mut rc_all: Vec<Vec<String>> = Vec::new();

    // rc ext (example)
    // NOTE: actual RC arrays are of type [Fp; t] and need conversion to hex strings
    for arr in RC3_EXT.iter() {
        let mut row = Vec::new();
        for &e in arr.iter() {
            // convert e (Fp) to hex string
            row.push(format!("{}", e)); // placeholder, adjust to fp_to_str if needed
        }
        rc_all.push(row);
    }
    // rc int
    for arr in RC3_INT.iter() {
        let mut row = Vec::new();
        for &e in arr.iter() {
            row.push(format!("{}", e)); // placeholder
        }
        rc_all.push(row);
    }

    let params = Params {
        t,
        d,
        fullRounds: 8,
        partialRounds: 56,
        mds,
        roundConstants: rc_all,
    };

    let s = serde_json::to_string_pretty(&params).unwrap();
    let mut f = File::create("constants.json").unwrap();
    f.write_all(s.as_bytes()).unwrap();

    println!("Wrote constants.json (注意：请根据 crate 实际 API 调整常数提取逻辑)");
}
