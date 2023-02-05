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