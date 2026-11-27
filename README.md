# Security audit: memcached/memcached

Date: 2026-11-27 | Auditor: [mutsuumii](https://github.com/mutsuumii)

## Summary

Found 198 issue(s): 19 critical, 179 high.

## Findings

### 1. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_tls.c` line 213

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
et->tls_wbuf = malloc(et->tls_wbuf_size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 2. [HIGH] Integer overflow in size calculation

**CWE-190** | `slab_automove_extstore.c` line 47

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
a->window_data = calloc(window_size * MAX_NUMBER_OF_SLAB_CLASSES, sizeof(struct window_data));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 3. [HIGH] Use-after-free pattern

**CWE-416** | `slab_automove_extstore.c` line 57

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(a);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 4. [HIGH] Use-after-free pattern

**CWE-416** | `slab_automove_extstore.c` line 71

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(a);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 5. [HIGH] Missing NULL check after allocation

**CWE-476** | `slab_automove_extstore.c` line 44

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
slab_automove *a = calloc(1, sizeof(slab_automove));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 6. [HIGH] Missing NULL check after allocation

**CWE-476** | `slab_automove_extstore.c` line 47

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
a->window_data = calloc(window_size * MAX_NUMBER_OF_SLAB_CLASSES, sizeof(struct window_data));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 7. [HIGH] Integer overflow in size calculation

**CWE-190** | `slab_automove.c` line 40

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
a->window_data = calloc(window_size * MAX_NUMBER_OF_SLAB_CLASSES, sizeof(struct window_data));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 8. [HIGH] Use-after-free pattern

**CWE-416** | `slab_automove.c` line 44

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(a);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 9. [HIGH] Use-after-free pattern

**CWE-416** | `slab_automove.c` line 58

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(a);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 10. [HIGH] Missing NULL check after allocation

**CWE-476** | `slab_automove.c` line 37

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
slab_automove *a = calloc(1, sizeof(slab_automove));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 11. [HIGH] Missing NULL check after allocation

**CWE-476** | `slab_automove.c` line 40

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
a->window_data = calloc(window_size * MAX_NUMBER_OF_SLAB_CLASSES, sizeof(struct window_data));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 12. [HIGH] Integer overflow in size calculation

**CWE-190** | `proxy_luafgen.c` line 180

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
fgen->list = realloc(fgen->list, fgen->free_max * sizeof(mcp_rcontext_t *));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 13. [HIGH] Integer overflow in size calculation

**CWE-190** | `proxy_luafgen.c` line 673

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
fgen->queue_list = realloc(fgen->queue_list, fgen->max_queues * sizeof(struct mcp_rqueue_s));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 14. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_luafgen.c` line 180

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
fgen->list = realloc(fgen->list, fgen->free_max * sizeof(mcp_rcontext_t *));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 15. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_luafgen.c` line 626

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
fgen->list = calloc(fgen->free_max, sizeof(mcp_rcontext_t *));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 16. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_luafgen.c` line 671

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
fgen->queue_list = malloc(sizeof(struct mcp_rqueue_s));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 17. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_luafgen.c` line 673

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
fgen->queue_list = realloc(fgen->queue_list, fgen->max_queues * sizeof(struct mcp_rqueue_s));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 18. [HIGH] Integer overflow in size calculation

**CWE-190** | `assoc.c` line 125

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
primary_hashtable = calloc(hashsize(hashpower + 1), sizeof(void *));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 19. [HIGH] Use-after-free pattern

**CWE-416** | `assoc.c` line 226

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(old_hashtable);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 20. [HIGH] Use-after-free pattern

**CWE-416** | `assoc.c` line 313

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(iter);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 21. [HIGH] Use-after-free pattern

**CWE-416** | `assoc.c` line 368

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(iter);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 22. [HIGH] Missing NULL check after allocation

**CWE-476** | `assoc.c` line 59

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
primary_hashtable = calloc(hashsize(hashpower), sizeof(void *));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 23. [HIGH] Missing NULL check after allocation

**CWE-476** | `assoc.c` line 125

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
primary_hashtable = calloc(hashsize(hashpower + 1), sizeof(void *));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 24. [HIGH] Missing NULL check after allocation

**CWE-476** | `assoc.c` line 305

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
struct assoc_iterator *iter = calloc(1, sizeof(struct assoc_iterator));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 25. [HIGH] Use-after-free pattern

**CWE-416** | `authfile.c` line 89

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(auth_data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 26. [HIGH] Use-after-free pattern

**CWE-416** | `authfile.c` line 109

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(main_auth_data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 27. [HIGH] Missing NULL check after allocation

**CWE-476** | `authfile.c` line 50

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
auth_data = calloc(1, sb.st_size + 2);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 28. [HIGH] Use-after-free pattern

**CWE-416** | `bipbuffer.c` line 60

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(me);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 29. [HIGH] Missing NULL check after allocation

**CWE-476** | `bipbuffer.c` line 51

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
bipbuf_t *me = malloc(bipbuf_sizeof(size));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 30. [HIGH] Use-after-free pattern

**CWE-416** | `slabs_mover.c` line 817

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(t);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 31. [HIGH] Missing NULL check after allocation

**CWE-476** | `slabs_mover.c` line 117

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
t->rebal.completed = (uint8_t*)calloc(perslab,sizeof(uint8_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 32. [HIGH] Missing NULL check after allocation

**CWE-476** | `slabs_mover.c` line 770

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
struct slab_rebal_thread *t = calloc(1, sizeof(*t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 33. [HIGH] Use-after-free pattern

**CWE-416** | `proxy_config.c` line 218

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(oldnamebuf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 34. [HIGH] Use-after-free pattern

**CWE-416** | `proxy_config.c` line 460

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(flist);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 35. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_config.c` line 44

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *nb = realloc(db->buf, db->size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 36. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_config.c` line 179

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *namebuf = calloc(1, namelen);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 37. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_config.c` line 424

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *flist = strdup(settings.proxy_startfile);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 38. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_config.c` line 434

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
struct _mcp_luafile *db = calloc(sizeof(struct _mcp_luafile), 1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 39. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_config.c` line 440

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
db->buf = calloc(db->size, 1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 40. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_config.c` line 441

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
db->fname = strdup(p);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 41. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_config.c` line 717

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
tus = calloc(1, sizeof(struct proxy_user_stats));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 42. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_config.c` line 725

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uint64_t *counters = calloc(stats_num, sizeof(uint64_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 43. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_request.c` line 217

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
rq->pr.vbuf = malloc(vlen);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 44. [HIGH] Use-after-free pattern

**CWE-416** | `crawler.c` line 201

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(d);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 45. [HIGH] Missing NULL check after allocation

**CWE-476** | `crawler.c` line 148

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *nb = realloc(c->buf, c->buflen);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 46. [HIGH] Missing NULL check after allocation

**CWE-476** | `crawler.c` line 164

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
d = calloc(1, sizeof(struct crawler_expired_data));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 47. [HIGH] Missing NULL check after allocation

**CWE-476** | `crawler.c` line 841

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
crawlc->buf = malloc(size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 48. [CRITICAL] Format string vulnerability

**CWE-134** | `restart.c` line 277

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
int vlen = vsnprintf(valbuf, SET_VAL_MAX-1, fmt, ap);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 49. [HIGH] Integer overflow in size calculation

**CWE-190** | `restart.c` line 76

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
char *metafile = calloc(1, flen + strlen(ext) + 1);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 50. [HIGH] Integer overflow in size calculation

**CWE-190** | `restart.c` line 226

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
char *metafile = calloc(1, flen + extlen + 1);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 51. [HIGH] Use-after-free pattern

**CWE-416** | `restart.c` line 88

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(metafile);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 52. [HIGH] Use-after-free pattern

**CWE-416** | `restart.c` line 126

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(metafile);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 53. [HIGH] Use-after-free pattern

**CWE-416** | `restart.c` line 176

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(line);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 54. [HIGH] Use-after-free pattern

**CWE-416** | `restart.c` line 204

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(line);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 55. [HIGH] Use-after-free pattern

**CWE-416** | `restart.c` line 210

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(line);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 56. [HIGH] Use-after-free pattern

**CWE-416** | `restart.c` line 241

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(metafile);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 57. [HIGH] Use-after-free pattern

**CWE-416** | `restart.c` line 254

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(metafile);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 58. [HIGH] Use-after-free pattern

**CWE-416** | `restart.c` line 262

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(metafile);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 59. [HIGH] Use-after-free pattern

**CWE-416** | `restart.c` line 351

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(memory_file);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 60. [HIGH] Missing NULL check after allocation

**CWE-476** | `restart.c` line 34

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
restart_data_cb *cb = calloc(1, sizeof(restart_data_cb));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 61. [HIGH] Missing NULL check after allocation

**CWE-476** | `restart.c` line 76

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *metafile = calloc(1, flen + strlen(ext) + 1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 62. [HIGH] Missing NULL check after allocation

**CWE-476** | `restart.c` line 226

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *metafile = calloc(1, flen + extlen + 1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 63. [HIGH] Missing NULL check after allocation

**CWE-476** | `restart.c` line 305

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
memory_file = strdup(file);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 64. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_internal.c` line 91

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
eio->buf = malloc(ntotal);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 65. [CRITICAL] Format string vulnerability

**CWE-134** | `memcached.h` line 167

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
klen = snprintf(key_str, STAT_KEY_LEN, name_fmt, num, name);    \
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 66. [CRITICAL] Format string vulnerability

**CWE-134** | `memcached.h` line 168

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
vlen = snprintf(val_str, STAT_VAL_LEN, fmt, val);               \
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 67. [HIGH] Missing NULL check after allocation

**CWE-476** | `memcached.h` line 1078

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
bool rbuf_switch_to_malloc(conn *c);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 68. [HIGH] Use-after-free pattern

**CWE-416** | `extstore.c` line 133

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(b);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 69. [HIGH] Use-after-free pattern

**CWE-416** | `extstore.c` line 299

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(e);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 70. [HIGH] Use-after-free pattern

**CWE-416** | `extstore.c` line 310

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(e);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 71. [HIGH] Use-after-free pattern

**CWE-416** | `extstore.c` line 315

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(e);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 72. [HIGH] Use-after-free pattern

**CWE-416** | `extstore.c` line 325

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(e);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 73. [HIGH] Use-after-free pattern

**CWE-416** | `extstore.c` line 334

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(e);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 74. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 128

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
_store_wbuf *b = calloc(1, sizeof(_store_wbuf));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 75. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 131

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
b->buf = calloc(size, sizeof(char));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 76. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 284

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
store_engine *e = calloc(1, sizeof(store_engine));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 77. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 330

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
e->pages = calloc(e->page_count, sizeof(store_page));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 78. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 364

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
e->free_page_buckets = calloc(cf->page_buckets, sizeof(store_page *));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 79. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 379

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
calloc(e->page_count, sizeof(struct extstore_page_data));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 80. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 384

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
e->page_buckets = calloc(cf->page_buckets, sizeof(store_page *));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 81. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 391

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
obj_io *io = calloc(1, sizeof(obj_io));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 82. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 406

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
e->io_threads = calloc(cf->io_threadcount, sizeof(store_io_thread));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 83. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 418

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
e->bg_thread = calloc(1, sizeof(store_io_thread));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 84. [HIGH] Missing NULL check after allocation

**CWE-476** | `extstore.c` line 432

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
st.page_data = calloc(e->page_count, sizeof(struct extstore_page_data));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 85. [HIGH] Integer overflow in size calculation

**CWE-190** | `proxy_lua.c` line 595

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
mcp_backend_t *be = calloc(1, sizeof(mcp_backend_t) + sizeof(struct mcp_backendconn_s) * bel->conncount);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 86. [HIGH] Integer overflow in size calculation

**CWE-190** | `proxy_lua.c` line 1406

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
struct proxy_hook_tagged *temp = realloc(h->tagged, sizeof(struct proxy_hook_tagged) * (h->tagcount+1));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 87. [HIGH] Use-after-free pattern

**CWE-416** | `proxy_lua.c` line 1716

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(sarg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 88. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_lua.c` line 331

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
be->logging.detail = malloc(tlen+1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 89. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_lua.c` line 595

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
mcp_backend_t *be = calloc(1, sizeof(mcp_backend_t) + sizeof(struct mcp_backendconn_s) * bel->conncount);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 90. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_lua.c` line 612

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
be->logging.detail = strdup(bel->logging.detail);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 91. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_lua.c` line 629

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
bec->rbuf = malloc(READ_BUFFER_SIZE);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 92. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_lua.c` line 636

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
bec->client = malloc(mcmc_size(MCMC_OPTION_BLANK));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 93. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_lua.c` line 1386

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
pht = calloc(1, sizeof(struct proxy_hook_tagged));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 94. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_lua.c` line 1406

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
struct proxy_hook_tagged *temp = realloc(h->tagged, sizeof(struct proxy_hook_tagged) * (h->tagcount+1));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 95. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_lua.c` line 1692

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *sarg = strdup(settings.proxy_startarg);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 96. [CRITICAL] Format string vulnerability

**CWE-134** | `proto_proxy.c` line 305

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
snprintf(key_str, STAT_KEY_LEN-1, "funcs_%s", name);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 97. [CRITICAL] Format string vulnerability

**CWE-134** | `proto_proxy.c` line 307

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
snprintf(key_str, STAT_KEY_LEN-1, "slots_%s", name);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 98. [CRITICAL] Format string vulnerability

**CWE-134** | `proto_proxy.c` line 335

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
snprintf(key_str, STAT_KEY_LEN-1, "bad_%s", name);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 99. [HIGH] Insecure random — cryptographic use

**CWE-338** | `proto_proxy.c` line 464

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
thr->proxy_rng[x] = rand();
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 100. [HIGH] Use-after-free pattern

**CWE-416** | `proto_proxy.c` line 1473

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(ptr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 101. [HIGH] Missing NULL check after allocation

**CWE-476** | `proto_proxy.c` line 351

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
proxy_ctx_t *ctx = calloc(1, sizeof(proxy_ctx_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 102. [HIGH] Missing NULL check after allocation

**CWE-476** | `proto_proxy.c` line 383

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
struct mcp_memprofile *prof = calloc(1, sizeof(struct mcp_memprofile));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 103. [HIGH] Missing NULL check after allocation

**CWE-476** | `proto_proxy.c` line 411

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
proxy_event_thread_t *t = calloc(1, sizeof(proxy_event_thread_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 104. [HIGH] Missing NULL check after allocation

**CWE-476** | `proto_proxy.c` line 428

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
thr->proxy_hooks = calloc(CMD_SIZE, sizeof(struct proxy_hook));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 105. [HIGH] Missing NULL check after allocation

**CWE-476** | `proto_proxy.c` line 433

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
thr->proxy_int_stats = calloc(1, sizeof(struct proxy_int_stats));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 106. [HIGH] Missing NULL check after allocation

**CWE-476** | `proto_proxy.c` line 444

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
struct mcp_memprofile *prof = calloc(1, sizeof(struct mcp_memprofile));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 107. [HIGH] Missing NULL check after allocation

**CWE-476** | `proto_proxy.c` line 475

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
proxy_event_thread_t *t = calloc(1, sizeof(proxy_event_thread_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 108. [HIGH] Missing NULL check after allocation

**CWE-476** | `proto_proxy.c` line 1191

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
c->item = malloc(pr.vlen);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 109. [HIGH] Missing NULL check after allocation

**CWE-476** | `proto_proxy.c` line 1476

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
return realloc(ptr, nsize);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 110. [HIGH] Missing NULL check after allocation

**CWE-476** | `linux_priv.c` line 51

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
kill_msg = malloc(strlen(KILL_MSG_STR)+1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 111. [HIGH] Use-after-free pattern

**CWE-416** | `storage.c` line 484

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
recache_or_free(pending);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 112. [HIGH] Use-after-free pattern

**CWE-416** | `storage.c` line 1189

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(readback_buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 113. [HIGH] Use-after-free pattern

**CWE-416** | `storage.c` line 1310

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(cf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 114. [HIGH] Missing NULL check after allocation

**CWE-476** | `storage.c` line 93

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
st.page_data = calloc(st.page_count, sizeof(struct extstore_page_data));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 115. [HIGH] Missing NULL check after allocation

**CWE-476** | `storage.c` line 306

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
eio->iov = malloc(sizeof(struct iovec) * IOV_MAX);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 116. [HIGH] Missing NULL check after allocation

**CWE-476** | `storage.c` line 820

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
st.page_data = calloc(st.page_count, sizeof(struct extstore_page_data));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 117. [HIGH] Missing NULL check after allocation

**CWE-476** | `storage.c` line 1120

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
readback_buf = malloc(settings.ext_wbuf_size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 118. [HIGH] Missing NULL check after allocation

**CWE-476** | `storage.c` line 1246

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
cf = calloc(1, sizeof(struct extstore_conf_file));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 119. [HIGH] Missing NULL check after allocation

**CWE-476** | `storage.c` line 1247

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
cf->file = strdup(p);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 120. [HIGH] Missing NULL check after allocation

**CWE-476** | `storage.c` line 1321

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
struct storage_settings *cf = calloc(1, sizeof(struct storage_settings));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 121. [HIGH] Use-after-free pattern

**CWE-416** | `proxy_network.c` line 216

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(be);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 122. [HIGH] Use-after-free pattern

**CWE-416** | `proxy_network.c` line 1515

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
event_config_free(ev_config);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 123. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_network.c` line 583

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
r->buf = malloc(r->blen + extra_space);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 124. [HIGH] Integer overflow in size calculation

**CWE-190** | `proxy_mutator.c` line 1236

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
rs->buf = malloc(total + run->vlen);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 125. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_mutator.c` line 1085

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
mut->arena = malloc(size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 126. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_mutator.c` line 1217

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
rq->pr.vbuf = malloc(run->vlen);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 127. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_mutator.c` line 1236

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
rs->buf = malloc(total + run->vlen);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 128. [HIGH] Use-after-free pattern

**CWE-416** | `proto_bin.c` line 646

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(dump_buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 129. [HIGH] Use-after-free pattern

**CWE-416** | `proto_bin.c` line 650

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(dump_buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 130. [CRITICAL] Format string vulnerability

**CWE-134** | `testapp.c` line 898

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
snprintf(buffer, sizeof(buffer), "gets ");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 131. [CRITICAL] Format string vulnerability

**CWE-134** | `testapp.c` line 901

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
offset += snprintf(buffer + offset, sizeof(buffer) - offset,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 132. [CRITICAL] Format string vulnerability

**CWE-134** | `testapp.c` line 920

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
int len = snprintf(buffer + 101, sizeof(buffer) - 101, "gets foo");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 133. [HIGH] Insecure random — cryptographic use

**CWE-338** | `testapp.c` line 995

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
num_bytes = (rand() % 1023) + 1;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 134. [HIGH] Insecure random — cryptographic use

**CWE-338** | `testapp.c` line 2036

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
uint8_t cmd = (uint8_t)(rand() & 0xff);
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 135. [HIGH] Insecure random — cryptographic use

**CWE-338** | `testapp.c` line 2038

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
size_t keylen = (rand() % 250) + 1;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 136. [CRITICAL] Command injection via system()/popen()

**CWE-78** | `testapp.c` line 515

system() and popen() invoke /bin/sh. Any unsanitized input in the command string gives full shell access.

```
system(coreadm);
```

**Fix:** Use execve() with explicit argv array. If shell features are needed, whitelist all arguments strictly.
---

### 137. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 94

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(con);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 138. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 220

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(alloc_objs);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 139. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 320

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 140. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 325

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 141. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 330

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 142. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 335

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 143. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 341

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 144. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 348

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 145. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 368

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 146. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 2018

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(response);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 147. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 2146

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buffer);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 148. [HIGH] Use-after-free pattern

**CWE-416** | `testapp.c` line 2164

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buffer);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 149. [HIGH] Missing NULL check after allocation

**CWE-476** | `testapp.c` line 199

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char ** alloc_objs = calloc(allocated_num, sizeof(char *));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 150. [HIGH] Missing NULL check after allocation

**CWE-476** | `testapp.c` line 2010

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
protocol_binary_response_no_extras *response = malloc(65*1024);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 151. [HIGH] Missing NULL check after allocation

**CWE-476** | `testapp.c` line 2136

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *buffer = malloc(buffersize);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 152. [CRITICAL] Format string vulnerability

**CWE-134** | `util.c` line 247

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
if (vsnprintf(buf, sizeof(buf), fmt, ap) == -1) {
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 153. [CRITICAL] Format string vulnerability

**CWE-134** | `proto_text.c` line 663

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
ret = snprintf(resp->wbuf + total, WRITE_BUFFER_SIZE - (it->nkey + 12),
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 154. [CRITICAL] Command injection via system()/popen()

**CWE-78** | `proto_text.c` line 811

system() and popen() invoke /bin/sh. Any unsanitized input in the command string gives full shell access.

```
i = system("sleep 0");
```

**Fix:** Use execve() with explicit argv array. If shell features are needed, whitelist all arguments strictly.
---

### 155. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_inspector.c` line 556

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ins->arena = malloc(size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 156. [CRITICAL] Format string vulnerability

**CWE-134** | `tls.c` line 299

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
snprintf(error_msg, errmax, "Error TLS not enabled\r\n");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 157. [CRITICAL] Format string vulnerability

**CWE-134** | `tls.c` line 317

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
err_msg_size = snprintf(error_msg, errmax, "Error loading the certificate chain: "
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 158. [CRITICAL] Format string vulnerability

**CWE-134** | `tls.c` line 322

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
err_msg_size = snprintf(error_msg, errmax, "Error loading the key: %s : %s",
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 159. [CRITICAL] Format string vulnerability

**CWE-134** | `tls.c` line 326

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
err_msg_size = snprintf(error_msg, errmax, "Error validating the certificate: %s",
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 160. [CRITICAL] Format string vulnerability

**CWE-134** | `tls.c` line 332

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
err_msg_size = snprintf(error_msg, errmax,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 161. [CRITICAL] Format string vulnerability

**CWE-134** | `tls.c` line 351

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
snprintf(error_msg, CRLF_NULLCHAR_LEN, "\r\n");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 162. [HIGH] Use-after-free pattern

**CWE-416** | `tls.c` line 97

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
SSL_free(ssl);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 163. [HIGH] Use-after-free pattern

**CWE-416** | `tls.c` line 138

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
X509_free(cert);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 164. [HIGH] Use-after-free pattern

**CWE-416** | `tls.c` line 144

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
X509_free(cert);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 165. [HIGH] Use-after-free pattern

**CWE-416** | `tls.c` line 150

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
X509_free(cert);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 166. [HIGH] Use-after-free pattern

**CWE-416** | `tls.c` line 154

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
X509_free(cert);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 167. [HIGH] Use-after-free pattern

**CWE-416** | `tls.c` line 306

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(error_msg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 168. [HIGH] Use-after-free pattern

**CWE-416** | `tls.c` line 344

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(ssl_err_msg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 169. [HIGH] Use-after-free pattern

**CWE-416** | `tls.c` line 347

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(error_msg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 170. [HIGH] Use-after-free pattern

**CWE-416** | `tls.c` line 361

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
SSL_free(ssl);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 171. [HIGH] Use-after-free pattern

**CWE-416** | `tls.c` line 414

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(error_msg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 172. [HIGH] Missing NULL check after allocation

**CWE-476** | `tls.c` line 304

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *ssl_err_msg = malloc(SSL_ERROR_MSG_SIZE);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 173. [HIGH] Use-after-free pattern

**CWE-416** | `proxy_ustats.c` line 45

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(entries);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 174. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_ustats.c` line 41

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
struct proxy_user_stats_entry *nentries = calloc(idx, sizeof(*entries));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 175. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_ustats.c` line 59

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
entries[idx].name = strdup(name);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 176. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_ustats.c` line 66

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
entries[idx].name = strdup(name);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 177. [HIGH] Missing NULL check after allocation

**CWE-476** | `proxy_ustats.c` line 69

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
entries[idx].name = strdup(name);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 178. [HIGH] Use-after-free pattern

**CWE-416** | `items.c` line 544

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
item_free(it);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 179. [HIGH] Use-after-free pattern

**CWE-416** | `items.c` line 1276

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(b);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 180. [HIGH] Use-after-free pattern

**CWE-416** | `items.c` line 1628

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(cdata);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 181. [HIGH] Missing NULL check after allocation

**CWE-476** | `items.c` line 654

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
buffer = malloc((size_t)memlimit);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 182. [HIGH] Missing NULL check after allocation

**CWE-476** | `items.c` line 926

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
stats_sizes_hist = calloc(stats_sizes_buckets, sizeof(int));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 183. [HIGH] Missing NULL check after allocation

**CWE-476** | `items.c` line 1269

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
lru_bump_buf *b = calloc(1, sizeof(lru_bump_buf));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 184. [HIGH] Missing NULL check after allocation

**CWE-476** | `items.c` line 1555

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
calloc(1, sizeof(struct crawler_expired_data));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 185. [HIGH] Integer overflow in size calculation

**CWE-190** | `xxhash.h` line 4455

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
xxh_u8* base = (xxh_u8*)XXH_malloc(s + align);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 186. [HIGH] Use-after-free pattern

**CWE-416** | `xxhash.h` line 1320

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
static void XXH_free(void* p) { free(p); }
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 187. [HIGH] Use-after-free pattern

**CWE-416** | `xxhash.h` line 1990

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
XXH_free(statePtr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 188. [HIGH] Use-after-free pattern

**CWE-416** | `xxhash.h` line 2421

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
XXH_free(statePtr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 189. [HIGH] Use-after-free pattern

**CWE-416** | `xxhash.h` line 4488

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
XXH_free(base);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 190. [HIGH] Missing NULL check after allocation

**CWE-476** | `xxhash.h` line 1314

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
static void* XXH_malloc(size_t s) { return malloc(s); }
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 191. [HIGH] Missing NULL check after allocation

**CWE-476** | `xxhash.h` line 1985

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
return (XXH32_state_t*)XXH_malloc(sizeof(XXH32_state_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 192. [HIGH] Missing NULL check after allocation

**CWE-476** | `xxhash.h` line 2416

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
return (XXH64_state_t*)XXH_malloc(sizeof(XXH64_state_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 193. [HIGH] Missing NULL check after allocation

**CWE-476** | `xxhash.h` line 4455

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
xxh_u8* base = (xxh_u8*)XXH_malloc(s + align);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 194. [HIGH] Use-after-free pattern

**CWE-416** | `logger.c` line 738

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(w);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 195. [HIGH] Use-after-free pattern

**CWE-416** | `logger.c` line 1025

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(l);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 196. [HIGH] Use-after-free pattern

**CWE-416** | `logger.c` line 1137

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(w);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 197. [HIGH] Missing NULL check after allocation

**CWE-476** | `logger.c` line 1018

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
logger *l = calloc(1, sizeof(logger));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 198. [HIGH] Missing NULL check after allocation

**CWE-476** | `logger.c` line 1120

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
w = calloc(1, sizeof(logger_watcher));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---
