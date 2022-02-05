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
    - Hints:
      1. 在一開始 `cnt == 3` 的情況下，我們什麼事情都不能做，因此必須要想辦法將 `cnt` 設為較大的數。而在此我們會需要用 fmt 來得到 cnt 的位址，並且寫值進去
      2. 在做 Step 1 時，可能會遇到一次不能寫入太大的值到 `cnt`，不過我們可以分成兩次做，一次先將次數增加到足夠做一次任意寫入，之後再將 `cnt` 寫成很大的值
      3. 如果我們能 bypass 掉 `exit()`，這樣就能控制 `ptr`，而首先我們必須要知道 `exit@got` 的位址，此時也能利用 fmt 做到 leak，並在 leak 後也透過 fmt 做到改寫 `exit@got`
      4. 之後基本上想做什麼就能做什麼，可以直接堆 ROP chain、或者是透過 `mprotect()` 執行任意 shellcode，但基本上都是透過 fmt 做 leak 與 partial overwrite
      5. 使用 fmt 的關鍵在於用 `%X$p` 來 leak、`%***c%k$hhn` 來做任意寫 (請參考投影片)，並且為了避免 timeout，在竄改時不一定要將目標位址整個改掉，可以做 partial overwrite 就好，並且通常寫入速度 `%hhn` > `%hn` >> `%n` (1 bytes / 2 bytes / 4 bytes)
    - PS:
      - `memset()` 在 local 跟 remote 會因為 CPU 支援的指令集的不同，動態解析到不同的 glibc function，所以如果 local 過 remote 不過，可能要重新算一下 offset，或者是從其他 function 的 got 來 leak
  - fullchain-nerf
    - Hints:
      1. 明顯有 stack overflow 可以控制 return address，並且也有 fmt 來 leak code / libc address，我們要考慮的只剩下要怎麼透過不多的 bof 來做到 ORW
      2. bof 能做的 ROP 沒辦法一次做完 ORW，然而卻可以執行 `read()` 並還有些許 gadget 可以執行，因此可以考慮先執行一次 read 的 ROP 來寫更多 gadgets
      3. 如果可以寫在後續的位址，或者是透過 stack pivoting 將 stack 遷移到其他地方，就可以將不足的 ROP chain 補完
  - sandbox
    - Hints:
      1. 雖然限制了一些 instruction，但是還是有其他指令可以控制程式執行流程，而且你要的東西其實程式就已經給你了

## Week 2: Binary Exploitation II
> 介紹 linux heap 中經常看到的結構與記憶體分配機制、講解簡單的 heap exploit 技巧如 tcache poisoning
- 影片: [video](https://youtu.be/A3kwWfex2XM)
- Lab
  - market
  - heapmath
- Hw
  - final (教學題)
  - easyheap
    1. 基本上跟 **final** 的解法三差不多，建議在練習 **final** 可以自己畫出 heap 結構，來幫助自己更熟悉 heap
  - beeftalk
    1. leak heap 位址很簡單，難點應該在於該如何 leak 出 libc，不過這題的設計洞很多，因此有許多不同的打法
    2. 這題是可以不用透過 `chat()` 內的 overflow 與 `unlink()` 的錯誤順序來做 exploit，只需要透過 user 建立與刪除的 bug 即可
    3. 可以想辦法從 freed chunk 留下的 smallbin 來 leak libc
    4. 可以想辦法讓 `name` 或是 `desc` 等可以在 `update()` 更新值的 member，與某個 `User` 結構做重疊，而後透過 UAF 來竄改 pointer 指向的位址
    5. 其他打法也有透過 `chat()` 的 overflow，或者甚至透過控制 `User->fifo` 的值來直接讀 `"/proc/self/maps"` 做 leak，或猜測檔名來直接讀 flag 的內容等等

## Week 3: FILE Exploitation & Browser Exploitation
> 講解 FILE 的結構以及利用技巧，並且對 browser pwn 做一些簡單的介紹
- 講者: Kia
- 影片: [video](https://youtu.be/1a-9iJn-csI)
- Slide1: [FILE Struct](https://docs.google.com/presentation/d/1DrdKADYM0VCUvfyw5GFN0fisOEX9CCt4H1zQgpofjJo/edit#slide=id.p2)
- Slide2: [Browser Pwn](https://docs.google.com/presentation/d/1BY8O5xKpopcf1jEFPMuvRXKYqilcZ7fexcHUFReEA0Y/edit#slide=id.p2)
- Lab
  - OvO8: [Download](https://drive.google.com/file/d/1vIMysdYS97pZ-sqrPqEORXGY5RIJp2VH/view?usp=sharing)
- Hw
  - FILE note: [Download](https://drive.google.com/file/d/1ABVJWtLjda8Z3_ZT4c9OnztIMFkvbq8A/view?usp=sharing)

## how2heap
> 針對 [how2heap](https://github.com/shellphish/how2heap) 中記載的 glibc 2.31 / 2.32 利用技巧加上部分中文註解以及分析

|                               | **2.31** | **2.32** | **2.34** |
| ----------------------------- | -------- | -------- | -------- |
| fastbin_dup                   | ✅        | ✅        | ✅        |
| fastbin_reverse_into_tcache   | ✅        | ✅        | ✅        |
| house_of_botcake              | ✅        | ✅        | ✅        |
| house_of_einherjar            | ✅        | ✅        | ✅        |
| house_of_lore                 | ✅        | ✅        | ✅        |
| house_of_mind_fastbin         | ✅        | ✅        | ✅        |
| large_bin_attack              | ✅        | ✅        | ✅        |
| mmap_overlapping_chunks       | ✅        | ✅        | ✅        |
| overlapping_chunks            | ✅        | ✅        | ✅        |
| poison_bull_byte              | ✅        | ✅        | ✅        |
| tcache_house_of_spirit        | ✅        | ✅        | ✅        |
| tcache_poisoning              | ✅        | ✅        | ✅        |
| tcache_stashing_unlink_attack | ✅        | ✅        | ✅        |
| unsafe_unlink                 | ✅        | ✅        | ✅        |
| decrypt_safe_linking          |          | ✅        | ✅        |
| bypass_safe_linking           |          | ✅        | ✅        |