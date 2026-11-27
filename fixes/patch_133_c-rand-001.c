# Insecure random — cryptographic use
# CWE-338 | Severity: HIGH
# File: testapp.c line 995

**Risk:** rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
