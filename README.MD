## Description

What's more fun than rewriting an already existing program? The learning process, of course.

This silly `discount-wget` downloads a file from the internet through HTTP or HTTPS, just like `wget` but with less features (Before writing this readme, I didn't know that `wget` could download file over FTP or download an entire website). At the moment, `discount-wget` doesn't follow redirects. This repository is only meant for learning.

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
