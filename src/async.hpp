#ifndef DISCOUNT_WGET_ASYNC_HPP
#define DISCOUNT_WGET_ASYNC_HPP

#include <cstdio>
#include <cstring>

#include "common.hpp"

project::tls_state_t initiate_tls_handshake(project::prog_t &);

project::prog_t *get_prog(uv_loop_t *loop)
{
    return reinterpret_cast<project::prog_t *>(loop->data);
}

int prepare_uvbuf(const char *base, size_t len, uv_buf_t **p_uvbuf)
{
    uv_buf_t *uvbuf = reinterpret_cast<uv_buf_t *>(malloc(sizeof(uv_buf_t)));
    uvbuf->base = reinterpret_cast<char *>(malloc(uvbuf->len = len));
    memcpy(uvbuf->base, base, len);
    *p_uvbuf = uvbuf;
    return 0;
}

void on_stream_close(uv_handle_t *handle)
{
    free(handle);
}

void on_shutdown(uv_shutdown_t *shutreq, int status)
{
    if (0 == status)
        uv_close(reinterpret_cast<uv_handle_t *>(shutreq->handle), on_stream_close);

    free(shutreq);
}

void cleanup_quick_write(uv_write_t *writereq)
{
    uv_buf_t *uvbuf = reinterpret_cast<uv_buf_t *>(writereq->data);

    project::uv_free(uvbuf);
    free(writereq);
}

void on_quick_write(uv_write_t *writereq, int status)
{
    uv_stream_t *stream = writereq->handle;
    if (0 != status)
    {
        fprintf(stderr, "error on quick write %p: %s\n", reinterpret_cast<void *>(stream), uv_err_name(status));
        uv_close(reinterpret_cast<uv_handle_t *>(stream), on_stream_close);
    }

    cleanup_quick_write(writereq);
}

int uv_quick_write(uv_stream_t *stream, uv_buf_t *uvbuf)
{
    uv_write_t *writereq = reinterpret_cast<uv_write_t *>(malloc(sizeof(uv_write_t)));
    writereq->data = reinterpret_cast<void *>(uvbuf);
    if (int retval = uv_write(writereq, stream, uvbuf, 1, on_quick_write); 0 != retval)
    {
        free(writereq);
        return retval;
    }

    return 0;
}

void uv_quick_alloc(uv_handle_t *_, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = reinterpret_cast<char *>(malloc(buf->len = suggested_size));
}

void on_fs_open(uv_fs_t *fsreq)
{
    if (0 > fsreq->result)
    {
        fprintf(stderr, "error couldn't open file: %s\n", uv_err_name(fsreq->result));
    }
    else
    {
        project::prog_t *prog = get_prog(fsreq->loop);

        prog->outfiled = fsreq->result;
        prog->outfiled_offset = 0;
    }

    free(fsreq);
}

void on_getaddrinfo(uv_getaddrinfo_t *uvreq, int status, struct addrinfo *result)
{
    project::prog_t *prog = get_prog(uvreq->loop);

    if (0 != status)
        fprintf(stderr, "error couldn't resolve %s with message: %s\n", prog->hostname, uv_err_name(status));
    else
        get_prog(uvreq->loop)->resolved = result;

    free(uvreq);
}

void on_data_read(uv_stream_t *, ssize_t, const uv_buf_t *);

int prepare_reqbuf(const char *hostname, const char *path, uv_buf_t **p_reqbuf)
{
    std::string httpreq = project::prepare_httpreq(hostname, path);
    return prepare_uvbuf(httpreq.c_str(), httpreq.length(), p_reqbuf);
}

void on_tcp_connect(uv_connect_t *connreq, int status)
{
    if (0 != status)
    {
        fprintf(stderr, "error couldn't connect: %s\n", uv_err_name(status));

        free(connreq);
        return;
    }

    uv_stream_t *client = connreq->handle;
    uv_read_start(client, uv_quick_alloc, on_data_read);

    project::prog_t *prog = get_prog(client->loop);

    switch (initiate_tls_handshake(*get_prog(client->loop)))
    {
    case project::tls_state_t::WANT_READ: // means OK!
        break;
    case project::tls_state_t::ERROR:
        fprintf(stderr, "error couldn't initiate TLS ClientHello\n");
        uv_close(reinterpret_cast<uv_handle_t *>(client), on_stream_close);
        break;
    case project::tls_state_t::NOT_HTTPS:
    {
        uv_buf_t *reqbuf;
        prepare_reqbuf(prog->hostname, prog->path, &reqbuf);
        if (int retval = uv_quick_write(client, reqbuf); 0 != retval)
        {
            uv_close(reinterpret_cast<uv_handle_t *>(client), on_stream_close);
            project::uv_free(reqbuf);
        }
        break;
    }
    }
    free(connreq);
}

void cleanup_fs_write(uv_fs_t *fwritereq)
{
    uv_buf_t *uvbuf = reinterpret_cast<uv_buf_t *>(fwritereq->data);

    project::uv_free(uvbuf);
    free(fwritereq);
}

void on_fs_close(uv_fs_t *fsreq)
{
    free(fsreq);
}

void uv_fclose(uv_loop_t *loop, uv_file file)
{
    uv_fs_t *fsreq = reinterpret_cast<uv_fs_t *>(malloc(sizeof(uv_fs_t)));
    uv_fs_close(loop, fsreq, file, on_fs_close);
}

void on_writeto(uv_fs_t *fwritereq)
{
    if (0 > fwritereq->result)
    {
        fprintf(stderr, "error couldn't write to file %lld: %s\n", fwritereq->file, uv_err_name(fwritereq->result));

        project::prog_t *prog = get_prog(fwritereq->loop);
        uv_close(reinterpret_cast<uv_handle_t *>(prog->client), on_stream_close);
        uv_fclose(prog->loop, fwritereq->file);
    }

    cleanup_fs_write(fwritereq);
}

int uv_writeto(uv_loop_t *loop, uv_file file, int64_t file_offset, uv_buf_t *writebuf)
{
    uv_fs_t *fwritereq = reinterpret_cast<uv_fs_t *>(malloc(sizeof(uv_fs_t)));
    fwritereq->data = reinterpret_cast<void *>(writebuf);
    if (int retval = uv_fs_write(loop, fwritereq, file, writebuf, 1, file_offset, on_writeto); 0 != retval)
    {
        free(fwritereq);
        return retval;
    }

    return 0;
}

#endif
