// disable squiggles first
#define USE_TCACHE 1

// ANCHOR 1. __libc_malloc(): malloc 的進入點
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim; // victim 會指向要被回傳的 chunk

  // ! 初始化 heap
  // 如果 __malloc_hook 有定義的話，就會以 __malloc_hook 為 function pointer 去呼叫
  // 一開始的 __malloc_hook 會存放用來初始化 heap 的 function "ptmalloc_init()"
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
#if USE_TCACHE // 預設會是 true
  size_t tbytes;
  // 會將 malloc size 做 alignment 後轉成 chunk size 存於 tbytes
  if (!checked_request2size (bytes, &tbytes))
    {
      __set_errno (ENOMEM);
      return NULL;
    }
  size_t tc_idx = csize2tidx (tbytes);
  // ! 初始化 tcache
  // 如果 tcache_perthread_struct 的結構還沒有被建立，則會呼叫 tcache_init()，
  // tcache_init() 會去請求 chunk size 為 0x290 的 chunk 給 tcache_perthread_struct，
  // 並將 tcache 的位址存放於 thread local storage 當中
  MAYBE_INIT_TCACHE ();

  // ! ---------------------- 第一、tcache ----------------------
  // 如果 tcache 對應的 index 內有 chunk 可以用 (tcache->counts[tc_idx] > 0)，
  // 就會透過 tcache_get() 取得 chunk 並回傳給使用者
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      return tcache_get (tc_idx);
    }
#endif

  if (SINGLE_THREAD_P) // 如果是 single thread
    {
      // ! 呼叫 malloc 的核心 function
      // 使用 _int_malloc (internal malloc) 從 main_arena 內儲存的資訊取出
      // chunk 回傳給使用者
      victim = _int_malloc (&main_arena, bytes);
      // 檢查 chunk: (不是 NULL || chunk 用 mmap 所建立 || main_arena 為 chunk 的 arena)
      // mem2chunk(): input 為使用者拿到的 chunk，output 為 chunk 的起頭
      // chunk2mem(): input 為 chunk 的起頭，output 為使用者拿到的 chunk
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

  // 下面的程式碼為 multit-hread 時才會使用到
  ...
}

// ANCHOR 2. tcache_get(): 從 tcache 中取得 chunk
static __always_inline void *
tcache_get (size_t tc_idx)
{
  // 從 tcache_perthread_struct 取出對應 index 的第一個 chunk
  tcache_entry *e = tcache->entries[tc_idx];
  // 更新對應 index 的第一個 chunk
  tcache->entries[tc_idx] = e->next;
  // counter--
  --(tcache->counts[tc_idx]);
  // 清除 key 來避免殘留 heap 位址
  e->key = NULL;
  return (void *) e;
}

// ANCHOR 3. _int_malloc(): ptmalloc 記憶體分配的核心機制
static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

#if USE_TCACHE
  size_t tcache_unsorted_count;	    /* count of unsorted chunks processed */
#endif

  // ! 將 malloc size 轉為 chunk size
  // 會將 malloc size 做 alignment 後轉成 chunk size 存於 nb
  if (!checked_request2size (bytes, &nb))
    {
      __set_errno (ENOMEM);
      return NULL;
    }

  // arena 為空，呼叫 sysmalloc() 來得到用 mmap() 產生的 chunk
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
	alloc_perturb (p, bytes);
      return p;
    }

  // ! ---------------------- 第二、fastbin ----------------------
  // 首先檢查 chunk size <= get_max_fast()，也就是 0x80
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb); // 取得 chunk size 在 fastbin 內的 idx
      // 取得 &main_arena.fastbinsY[idx]
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp;
      victim = *fb; // 要回傳的即是指向的第一塊 chunk

      if (victim != NULL)
	{
	  if (SINGLE_THREAD_P)
	    *fb = victim->fd; // 更新第一塊 chunk
	  
	  if (__glibc_likely (victim != NULL))
	    {
        // 取得 chunk 結構紀錄的 size 所對應到的 idx
        // 比較是否與 chunk size 對應到的 idx 相同
        // 即為：如果回傳的 chunk 的大小不該屬於此 fastbin，則被判斷為 corrupt
	      size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
	      // 此機制稱 tcache stash
        // 如果 fastbin 還有剩 chunk，就會嘗試把這些 chunk 放到 tcache 當中
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins
          /* mp 為 malloc parameter，記錄一些 metadata */)
		{
		  mchunkptr tc_victim;

		  // 當 (fastbin 還有 chunk && tcache 還沒滿)
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (SINGLE_THREAD_P)
			    *fb = tc_victim->fd;
              // 放入 tcache 當中
		      tcache_put (tc_victim, tc_idx);
		    }
		} // 可以發現 fastbin chunk 會以 reverse order 放入 tcache
          // 原本在 fastbin 的第一塊 chunk，在經過 tcache stash 後會變成
          // 這些 fastbin chunk 中的最後一塊
#endif
          // 轉成回傳給使用者 mem ptr
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;
	    }
	}
    }

  // ! ---------------------- 第三、smallbin ----------------------
  // 如果 chunk 落於 smallbin 的大小當中，也就是 0x20 ~ 0x3f0
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb); // 取得 smallbin 對應到的 index
      bin = bin_at (av, idx); // 取得 main_arena 中對應 index 的 smallbin 位址

      // last(chk) 會得到 chk->bk
      // first(chk) 會得到 chk->fd
      // condition 為 chk->bk != chk，而在初始化時 smallbin 會將 fd 與 bk 設為自己，
      // 也就是這個 condition 檢查此 index 的 smallbin 是否為空
      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
      // chk->bk->fd 應該要指向自己，才會是正常的 double linked list
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          // set 下一塊的 chunk 的 prev_inuse bit 
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck; // 更新 chk->bk 為該 idx 的 smallbin 的第一塊 chunk
          bck->fd = bin; // 更新 chk->bk->fd 原先指向 chk，更新成 smallbin

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  // 此機制稱 smallbin stash，與 tcache stash 相同
    // 如果 smallbin 還有剩 chunk，就會嘗試把這些 chunk 放到 tcache 當中
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			    set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	        }
		}
	    }
#endif
          // 轉成回傳給使用者 mem ptr
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
  else
    {
      // 如果 chunk size 不在 tcache, fastbin, smallbin 的範圍
      // trigger malloc_consolidate 的機制，減少 fragmentation 的問題
      idx = largebin_index (nb);
      if (atomic_load_relaxed (&av->have_fastchunks))
        malloc_consolidate (av);
    }

#if USE_TCACHE
  INTERNAL_SIZE_T tcache_nb = 0;
  size_t tc_idx = csize2tidx (nb); // 取得對應大小的 tcache idx  
  if (tcache && tc_idx < mp_.tcache_bins)
    tcache_nb = nb;
  int return_cached = 0;

  tcache_unsorted_count = 0;
#endif

  for (;; )
    {
      int iters = 0;
      // ! ---------------------- 第四、unsorted bin ----------------------
      // 以 bk 來 traverse 所有 unsorted bin chunk
      // 清空 unsorted bin，把 chunk 放到對應的 bin 當中
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk; // bck 為 unsorted bin 下個 chunk
          size = chunksize (victim); // 當前 chunk 的大小
          mchunkptr next = chunk_at_offset (victim, size); // 下個相鄰的 chunk

          // 一系列的檢查
          if (__glibc_unlikely (size <= 2 * SIZE_SZ)
              || __glibc_unlikely (size > av->system_mem))
            // chunk size 是否合法
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            // next chunk size 不合法
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            // next chunk 的 prev_size 不等於 chunk size
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            // 當 (bck->fd (victim->bk->fd) != victim ||
            // victim->fd 沒有指向 main_arena 中存放 unsorted bin 的位址) 時不合法
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            // next chunk 的 prev_inuse 設起但是當前 chunk 存在於 unsorted bin (freed)
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
          
          // 請求大小屬於 smallbin 的範圍，並且 unsorted bin 的第一個 chunk 就是 last_remainder
          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
              // 這邊加上 MINSIZE 的關係為，在從 unsorted chunk 切後，剩下的 chunk size
              // 應該要能符合最小塊 chunk 的大小 (0x20)
            {
              // 切出符合大小的 chunk 後，更新 last_remainder
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              // unsortedbin 的 fd 與 bk 更新成指向 remainder
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              // remainder 的 fd 與 bk 更新成指向 unsortedbin
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

          // 從 unsorted bin 當中移除 victim
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          // 第一塊 chunk 的 size 剛好符合 request size
          if (size == nb)
          {
            set_inuse_bit_at_offset (victim, size); // 設為 inuse
            // 如果 tcache 還沒滿，就優先填滿 tcache
            if (tcache_nb && tcache->counts[tc_idx] < mp_.tcache_count)
            {
              tcache_put (victim, tc_idx);
              return_cached = 1;
              continue;
            }
            else // tcache 滿了，就直接回傳
            {
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
          }

          // 如果為 smallbin 的大小，放入 smallbin
          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else
            {
              // 如果為 largebin 的大小，放入 largebin
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              // 當 largebin 不只有一個 chunk，在 insert 到 largebin 時處理排序
              if (fwd != bck)
                {
                  ...
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }

          // 統一處理 smallbin 與 largebin 更新 fd, bk pointer 的操作
          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

          // 若在同一輪處理太多 chunk，並且在過程中有放入 chunk 到 tcache 內 (return_cached == 1)
          // 則直接從 tcache 取得一個 chunk 回傳
          ++tcache_unsorted_count;
          if (return_cached
            && mp_.tcache_unsorted_limit > 0
            && tcache_unsorted_count > mp_.tcache_unsorted_limit)
          {
            return tcache_get (tc_idx);
          }

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS) // 做太多次就 break
            break;
        }

        // 過程中有將相同大小的 chunk 放入 tcache 的話，直接回傳一個
        if (return_cached)
        {
          return tcache_get (tc_idx);
        }

      // ! ---------------------- 第五、large bin ----------------------
      // 如果大小不屬於 smallbin 的範圍，屬於 smallbin 的已經在 "第三、smallbin" 處理完了
      if (!in_smallbin_range (nb))
        {
          bin = bin_at (av, idx); // 取得對應 idx 的 largebin 位址

          // largebin 要不為空，並且最大塊的大小要大於 request size
          if ((victim = first (bin)) != bin
              && (unsigned long) chunksize_nomask (victim)
              >= (unsigned long) (nb))
            {
              // 省略處理 large bin 的過程
              // 會找 best fit 的 largebin chunk 回傳給使用者
              ...
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }

      // 當符合 request size 的 largebin 沒有 chunk 可以用，
      // 會開始往後面的 largebin 開始找
      ++idx;
      bin = bin_at (av, idx);
      block = idx2block (idx);
      map = av->binmap[block];
      bit = idx2bit (idx);

      // traverse all largebin
      for (;; )
        {
          // 省略處理 large bin 的過程
          ...
          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }

    // ! 當所有 bin 都沒有可以使用的 chunk，則從 top chunk 開始切
    use_top:
      victim = av->top;
      size = chunksize (victim);

      if (__glibc_unlikely (size > av->system_mem))
        malloc_printerr ("malloc(): corrupted top size");

      // 如果 top chunk 的大小滿足 request size + 0x20，就直接切並回傳
      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
      // ! 請求過大
      // 如果 top chunk 小到沒辦法切，會根據 request size，
      // 透過 sysmalloc 擴展更大的空間後回傳給使用者
      else
        {
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);
          return p;
        }
    }
}