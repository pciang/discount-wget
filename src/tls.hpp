#ifndef DISCOUNT_WGET_TLS_HPP
#define DISCOUNT_WGET_TLS_HPP

#include "openssl/bio.h"

#include "common.hpp"

namespace project
{
    enum class flush_wbio_t : int
    {
        OK = 0,
        EMPTY
    };
};

project::flush_wbio_t flush_wbio(SSL *ssl, std::unique_ptr<uv_buf_t> &uvbuf)
{
    BIO *wbio = SSL_get_wbio(ssl);

    int npending = BIO_pending(wbio);
    if (0 >= npending)
        return project::flush_wbio_t::EMPTY;

    std::unique_ptr<uv_buf_t> temp(reinterpret_cast<uv_buf_t *>(malloc(sizeof(uv_buf_t))));
    uvbuf.swap(temp);
    uvbuf->base = reinterpret_cast<char *>(malloc(uvbuf->len = npending));

    BIO_read(wbio, reinterpret_cast<void *>(uvbuf->base), npending);
    return project::flush_wbio_t::OK;
}

int flush_uv_readbuf(SSL *ssl, const uv_buf_t *readbuf, ssize_t nread)
{
    return BIO_write(SSL_get_rbio(ssl), reinterpret_cast<void *>(readbuf->base), nread);
}

int ssl_quick_peek(SSL *ssl)
{
    char placeholder[4];
    return SSL_peek(ssl, placeholder, sizeof(placeholder));
}

project::flush_wbio_t ssl_quick_read(SSL *ssl, std::unique_ptr<uv_buf_t> &uvbuf)
{
    ssl_quick_peek(ssl);

    int npending = SSL_pending(ssl);
    if (0 >= npending)
        return project::flush_wbio_t::EMPTY;

    std::unique_ptr<uv_buf_t> temp(reinterpret_cast<uv_buf_t *>(malloc(sizeof(uv_buf_t))));
    uvbuf.swap(temp);
    uvbuf->base = reinterpret_cast<char *>(malloc(uvbuf->len = npending));

    SSL_read(ssl, uvbuf->base, npending);
    return project::flush_wbio_t::OK;
}

#endif
