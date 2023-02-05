// disable squiggles first
#define USE_TCACHE 1

// ANCHOR 1. __libc_free(): free 的進入點
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  // 如果 __free_hook 有定義的話，就會以 __free_hook 為 function pointer 去呼叫
  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }
  // free NULL 會直接回傳
  if (mem == 0)
    return;
  // chunk2mem(): input 為 chunk 的起頭，output 為使用者拿到的 chunk
  // mem2chunk(): input 為使用者拿到的 chunk，output 為 chunk 的起頭
  p = mem2chunk (mem);

  // ! 如果 chunk 是透過 mmap() 產生的，則會使用 unmap 來釋放
  if (chunk_is_mmapped (p))
    {
      ...
      munmap_chunk (p);
      return;
    }
  // 通常在 malloc 時會已經初始化完 tcache
  MAYBE_INIT_TCACHE ();
  // 檢查 chunk 的 NON_MAIN_ARENA bit，如果是 unset，則回傳 main_arena
  // 否則回傳 chunk 所屬的 heap 其對應到的 arena
  ar_ptr = arena_for_chunk (p);
  // ! _int_free 用來處理釋放記憶體的操作
  _int_free (ar_ptr, p, 0);
}

// ANCHOR 2 _int_free(): ptmalloc 記憶體釋放的核心機制
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  // 取得 chunk size
  size = chunksize (p);

  // chunk pointer 需要 aligned，也不會在 address space 的結尾
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  // chunk 至少要大於 MINSIZE (0x20) 並且對其 MALLOC_ALIGNMENT (0x10)
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");

  // ! ---------------------- 第一、tcache ----------------------
  {
    size_t tc_idx = csize2tidx (size); // 取得 chunk size 對應到的 tcache idx
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
		// 檢查 chunk 是否已經存在於 tcache 當中
		tcache_entry *e = (tcache_entry *) chunk2mem (p);

		// 將此 chunk 視為 tcache entry 的話，對應 key 的位置極少可能是 tcache 的位址
		// 所以條件滿足的話要進行額外的檢查
		if (__glibc_unlikely (e->key == tcache))
		{
			tcache_entry *tmp;
			// traverse 此 tcache bin 每個 entry，看是否有與要釋放的 chunk 相同
			for (tmp = tcache->entries[tc_idx];
			tmp;
			tmp = tmp->next)
			if (tmp == e)
			malloc_printerr ("free(): double free detected in tcache 2");
		}

		// 如果對應的 tcache bin 還沒滿，就放到當中並 return
		if (tcache->counts[tc_idx] < mp_.tcache_count)
		{
			tcache_put (p, tc_idx);
			return;
	  }
      }
  }
  // ! ---------------------- 第二、fastbin ----------------------
	// 若 chunk size 在 fastbin 的範圍中
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())) {
	// 檢查下個 chunk 的大小是否在合法範圍內
    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
	{
		bool fail = true;
		if (fail)
		malloc_printerr ("free(): invalid next size (fast)");
	}

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    atomic_store_relaxed (&av->have_fastchunks, true);
    unsigned int idx = fastbin_index(size); // 取得對應大小的 fastbin idx
    fb = &fastbin (av, idx); // 取得對應 idx 的 fastbin 位址

    // old 為 fastbin 中的第一個 chunk
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)
      {
		// 如果即將被釋放的 chunk == fastbin 的第一個 chunk，則發生 double free
		if (__builtin_expect (old == p, 0))
			malloc_printerr ("double free or corruption (fasttop)");
			p->fd = old;
			*fb = p;
      }
	  else
	  {
		  // multithread case
		  ...
	  }
  }

  // 如果 chunk 並非使用 mmap() 所建立
  else if (!chunk_is_mmapped(p)) {
	// ! ---------------------- 第三、unsorted bin ----------------------
    /* If we're single-threaded, don't lock the arena.  */
    if (SINGLE_THREAD_P)
      have_lock = true;

	// 取得下個相鄰 chunk 的位址
    nextchunk = chunk_at_offset(p, size);

	// 要釋放的 chunk 為 top chunk
    if (__glibc_unlikely (p == av->top))
      malloc_printerr ("double free or corruption (top)");
	// 要下個 chunk 的位址已經超過 boundaries
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
	malloc_printerr ("double free or corruption (out)");
	// 要釋放的 chunk 已經被下個 chunk mark 成沒在使用 (prev_inuse == 0)
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");

	// 取得下個相鄰 chunk 的大小
    nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
	  // 下個 chunk 的大小不合法
      malloc_printerr ("free(): invalid next size (normal)");

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

	// 上個相鄰 chunk 沒在使用，將他們合併
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }

	// 下個相鄰 chunk 若不是 top chunk
    if (nextchunk != av->top) {
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
      // 如果下下個 chunk 的 prev_inuse == 0，代表下個 chunk 沒在用，
	  // 就 consolidate 下個 chunk
      if (!nextinuse) {
		unlink_chunk (av, nextchunk);
		size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);

	  // 將 chunk 放到 unsorted bin 當中
      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
		malloc_printerr ("free(): corrupted unsorted chunks");
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
	  // 更新 fd 與 bk
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }
	// 下個相鄰 chunk 是 top chunk，直接與 top chunk 合併
    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }

    // FASTBIN_CONSOLIDATION_THRESHOLD == 65536
	// 當釋放掉的 chunk 大小超過 65536 (0x10000)，會 trigger malloc_consolidate()
	// 合併掉 fastbin 內的 chunk 來減少 fragmentation
    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      ...
	    malloc_consolidate(av);
    }

	// trim memory 的操作
      if (av == &main_arena) { ... /* single thread case */ }
	  else { ... /* multithread case */ }
  }
  // ! 如果 chunk 用 mmap() 建立，則用 munmap 來釋放
  else {
    munmap_chunk (p);
  }
}

// ANCHOR 3. tcache_put(): 釋放 chunk 至 tcache
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  // 將 key member 設為 tcache，藉此來偵測 double free
  e->key = tcache;
  // 更新指向下一個的 chunk
  e->next = tcache->entries[tc_idx];
  // 更新 tcache_perthread_struct 指向的第一個 chunk
  tcache->entries[tc_idx] = e;
  // counter++
  ++(tcache->counts[tc_idx]);
}

// ANCHOR 4. malloc_consolidate(): glibc 用於減少 fragmentation 的合併機制，與 free() 內部的實作類似，但是主要用來處理 fastbin
static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;

  atomic_store_relaxed (&av->have_fastchunks, false);

  unsorted_bin = unsorted_chunks(av);

  // 合併 fastbin 當中的 chunk，並且將合併後的 chunk 放入 unsorted bin 當中

  maxfb = &fastbin (av, NFASTBINS - 1); // 取得 fastbin 最大的 index
  fb = &fastbin (av, 0); // 取得 &main.fastbinsY
  do {
    p = atomic_exchange_acq (fb, NULL);
    if (p != 0) {
      do {

	{
	  unsigned int idx = fastbin_index (chunksize (p));
	  if ((&fastbin (av, idx)) != fb)
	    malloc_printerr ("malloc_consolidate(): invalid chunk size");
	}

	nextp = p->fd; // 取得下一塊 chunk

  // ! ------- 先往上個 merge -------
	size = chunksize (p); // chunk szie
	nextchunk = chunk_at_offset(p, size); // 下一個 chunk 的位址
	nextsize = chunksize(nextchunk); // 下一個 chunk 的 chunk size

	if (!prev_inuse(p)) { // 如果 chunk 的 prev_inuse 沒設，代表上一塊沒有用
	  prevsize = prev_size (p); // 取得上塊的大小
	  size += prevsize;
	  p = chunk_at_offset(p, -((long) prevsize)); // 取得上一塊 chunk 的位址
	  // 檢查上塊 chunk size 是否與紀錄的 size 相同
	  if (__glibc_unlikely (chunksize(p) != prevsize))
	    malloc_printerr ("corrupted size vs. prev_size in fastbins");
	  // 將上個 chunk 從原本所屬的 bin 取出
	  unlink_chunk (av, p);
	}

  // ! ------- 再往下個 merge -------
	if (nextchunk != av->top /* 下個不是 top chunk，也就是並非最後一塊 chunk */) {
	  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	  // 如果下一塊沒在用
	  if (!nextinuse) {
	    size += nextsize;
	  // 將下個 chunk 從原本所屬的 bin 取出
	    unlink_chunk (av, nextchunk);
	  } else
	    clear_inuse_bit_at_offset(nextchunk, 0); // unset 下一塊 chunk 的 prev_inuse

      // unsorted 的第一塊
	  first_unsorted = unsorted_bin->fd;
	  unsorted_bin->fd = p; // 更新 unsorted bin 的第一塊
	  first_unsorted->bk = p; // 原本的第一塊，變成第二塊

	  // 如果並非在 smallbin 的範圍，則清除殘留的 fd_nextsize 與 bk_nextsize
	  if (!in_smallbin_range (size)) {
	    p->fd_nextsize = NULL;
	    p->bk_nextsize = NULL;
	  }

	  // 放入 unsorted bin 當中
	  set_head(p, size | PREV_INUSE);
	  p->bk = unsorted_bin;
	  p->fd = first_unsorted;
	  set_foot(p, size);
	}

	else { // 由於下一塊為 top chunk，會直接被 merge 到 top chunk 當中
	  size += nextsize;
	  set_head(p, size | PREV_INUSE);
	  av->top = p;
	}

      } while ( (p = nextp) != 0); // update 要檢查的下個 chunk，即是 chk->fd

    }
  } while (fb++ != maxfb); // traverse 所有 fastbin
}