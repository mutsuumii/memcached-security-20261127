# Missing NULL check after allocation
# CWE-476 | Severity: HIGH
# File: proxy_mutator.c line 1236

**Risk:** Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
