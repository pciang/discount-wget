## Description

What's more fun than rewriting an already existing program? The learning process, of course.

This silly `discount-wget` downloads a file from the internet through HTTP or HTTPS, just like `wget` but with less features (Before writing this readme, I didn't know that `wget` could download a file over FTP or download an entire website). ~~At the moment, `discount-wget` doesn't follow redirects.~~ `discount-wget` now follows redirect once. This repository is only meant for learning.

### Dependencies

* `libuv`: takes care of async I/O and event loop
* `libcurl`: only to parse URL
* `llhttp`: parses HTTP response
* `openssl`: handles TLS

### Build

1. You'll need a VSCode with the C/C++ extension.
2. You'll need to install `libuv`, `libcurl` and `openssl`.
3. Follow the build instruction in `llhttp`.
4. Launch `Compile and run discount-wget` from VSCode.

### Example

Build and run `discount-wget`. Try to download a relatively big file, e.g. Pgadmin4, which is about 210MB.

```
./build/main -o pgadmin4.dmg https://ftp.postgresql.org/pub/pgadmin/pgadmin4/v8.1/macos/pgadmin4-8.1-x86_64.dmg
md5 pgadmin4.dmg
```

Output:

```
MD5 (pgadmin4.dmg) = 22c62e3b61db9d25b6d67af50f54aa81
```

Verify this by downloading the `.dmg` file through a browser:

```
md5 ~/Downloads/pgadmin4-8.1-x86_64.dmg
```

Output:

```
MD5 (Downloads/pgadmin4-8.1-x86_64.dmg) = 22c62e3b61db9d25b6d67af50f54aa81
```
