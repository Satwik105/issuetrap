### Bug: login button does nothing on Safari 17

**Steps to reproduce**
1. Open https://example.com/login in Safari 17.2
2. Enter a valid email and password
3. Click "Sign in"

**Expected:** redirect to /dashboard
**Actual:** nothing happens. The console shows `TypeError: undefined is not an object`.

<!-- Please include your browser version and OS. -->

I tried clearing the cache and disabling extensions. Happy to test a fix.
