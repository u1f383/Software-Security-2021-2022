# 2021 交大程式安全 binary exploit 教材
這個 repo 為 2021 年交大的程式安全，Pwn 課程的前兩週教材，第三週由另一名助教 @kia 所負責。

repo 目錄的結構如下：
```
.
├── Dockerfile # 建構 pwnbox
├── snippet # pwnbox 的執行腳本
├── week1
│   ├── Pwn-w1.pdf # 投影片
│   ├── demo # 範例
│   │   ├── demo1
│   │   └── ...
│   ├── hw # 作業
│   │   ├── hw1
│   │   ├── ...
│   │   └── exp # 在 deadline 結束後會更新參考解答
│   └── lab # 課堂習題
│       ├── lab1
│       ├── ...
│       └── exp
├── week2
├── quals # AIS3 EOF qualify 題目
...
```

## Week 1: Binary Exploitation I
> linux 相關的基礎知識如 ELF struct 與 calling convention、介紹不同的保護機制與攻擊方法
- 影片: [video](https://youtu.be/ktoVQB99Gj4)
- Lab
  - Got2win
  - Rop2win
- Hw
  - fullchain
  - fullchain-nerf
  - sandbox

## Week 2: Binary Exploitation II
> 介紹 linux heap 中經常看到的結構與記憶體分配機制、講解簡單的 heap exploit 技巧如 tcache poisoning
- 影片: [video](https://youtu.be/A3kwWfex2XM)
- Lab
  - market
  - heapmath
- Hw
  - easyheap
  - beeftalk
  - final