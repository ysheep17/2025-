#### 1. 直接访问S盒
- **优化点**：删除仅用于返回S盒值的`sm4Sbox`函数，直接通过数组索引访问Sbox
- **代码变更**：
  ```cpp:c:\Users\杨\Desktop\2024expriment\2025chuangxinshijian\task1\原始\sm4.cpp
  // 替换前
  b[0] = sm4Sbox(a[0]);
  // 替换后
  b[0] = Sbox[a[0]];
  ```


#### 2. 轮密钥生成循环展开
- **优化点**：将32轮密钥生成循环从单轮迭代改为4轮并行计算
- **代码变更**：
  ```cpp:c:\Users\杨\Desktop\2024expriment\2025chuangxinshijian\task1\原始\sm4.cpp
  // 替换前
  for(;i<32;i++){
      k[i+4] = k[i]^sm4CaliRk(k[i+1]^k[i+2]^k[i+3]^CK[i]);
      SK[i] = k[i+4];
  }
  // 替换后
  for(i=0; i<32; i+=4){
      k[i+4] = k[i]^sm4CaliRk(k[i+1]^k[i+2]^k[i+3]^CK[i]);
      SK[i] = k[i+4];
      k[i+5] = k[i+1]^sm4CaliRk(k[i+2]^k[i+3]^k[i+4]^CK[i+1]);
      SK[i+1] = k[i+5];
      // ... 每次循环处理4轮 ...
  }
  ```


#### 3. 加密轮函数循环展开
- **优化点**：将32轮加密主循环从单轮迭代改为4轮并行计算
- **代码变更**：
  ```cpp:c:\Users\杨\Desktop\2024expriment\2025chuangxinshijian\task1\原始\sm4.cpp
  // 替换前
  while(i<32)
  {
      ulbuf[i+4] = sm4F(ulbuf[i], ulbuf[i+1], ulbuf[i+2], ulbuf[i+3], sk[i]);
      i++;
  }
  // 替换后
  for(i=0; i<32; i+=4)
  {
      ulbuf[i+4] = sm4F(ulbuf[i], ulbuf[i+1], ulbuf[i+2], ulbuf[i+3], sk[i]);
      ulbuf[i+5] = sm4F(ulbuf[i+1], ulbuf[i+2], ulbuf[i+3], ulbuf[i+4], sk[i+1]);
      ulbuf[i+6] = sm4F(ulbuf[i+2], ulbuf[i+3], ulbuf[i+4], ulbuf[i+5], sk[i+2]);
      ulbuf[i+7] = sm4F(ulbuf[i+3], ulbuf[i+4], ulbuf[i+5], ulbuf[i+6], sk[i+3]);
  }
  ```
