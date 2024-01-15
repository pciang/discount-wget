#ifndef DISCOUNT_WGET_ASYNC_HPP
#define DISCOUNT_WGET_ASYNC_HPP

#include <cstdio>
#include <cstring>

#include "common.hpp"

project::tls_state_t initiate_tls_handshake(const project::client_t &);

project::client_t *get_client(uv_stream_t *stream)
{
    return reinterpret_cast<project::client_t *>(stream->data);
}

project::prog_t *get_prog(uv_stream_t *stream)
{
    return reinterpret_cast<project::prog_t *>(uv_loop_get_data(stream->loop));
}

project::prog_t *get_prog(uv_loop_t *uvloop)
{
    return reinterpret_cast<project::prog_t *>(uv_loop_get_data(uvloop));
}

int prepare_uvbuf(const char *base, size_t len, std::unique_ptr<uv_buf_t> &uvbuf)
{
    std::unique_ptr<uv_buf_t> temp(reinterpret_cast<uv_buf_t *>(malloc(sizeof(uv_buf_t))));
    uvbuf.swap(temp);
    uvbuf->base = reinterpret_cast<char *>(malloc(uvbuf->len = len));

    memcpy(uvbuf->base, base, len);
    return 0;
}

void on_stream_close(uv_handle_t *handle) {}

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
    uv_stream_t *tcphandle = writereq->handle;
    if (0 != status)
    {
        fprintf(stderr, "error on quick write %p: %s\n", reinterpret_cast<void *>(tcphandle), uv_err_name(status));
        uv_close(reinterpret_cast<uv_handle_t *>(tcphandle), on_stream_close);
    }

    cleanup_quick_write(writereq);
}

int uv_quick_write(uv_stream_t *tcphandle, uv_buf_t *uvbuf)
{
    uv_write_t *writereq = reinterpret_cast<uv_write_t *>(malloc(sizeof(uv_write_t)));
    writereq->data = reinterpret_cast<void *>(uvbuf);
    if (int retval = uv_write(writereq, tcphandle, uvbuf, 1, on_quick_write); 0 != retval)
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
        project::prog_t &prog = *get_prog(fsreq->loop);

        prog.outfiled = fsreq->result;
        prog.outfiled_offset = 0;
    }

    free(fsreq);
}

void on_getaddrinfo(uv_getaddrinfo_t *uvreq, int status, struct addrinfo *result)
{
    project::prog_t &prog = *get_prog(uvreq->loop);
    project::client_t &client = *prog.active;

    if (0 != status)
        fprintf(stderr, "error couldn't resolve %s with message: %s\n", client.hostname.get(), uv_err_name(status));
    else
    {
        std::unique_ptr<addrinfo> _tmp(result);
        client.resolved.swap(_tmp);
    }

    free(uvreq);
}

void on_data_read(uv_stream_t *, ssize_t, const uv_buf_t *);

int prepare_reqbuf(const char *hostname, const char *path, std::unique_ptr<uv_buf_t> &reqbuf)
{
    std::string httpreq = project::prepare_httpreq(hostname, path);
    return prepare_uvbuf(httpreq.c_str(), httpreq.length(), reqbuf);
}

void on_tcp_connect(uv_connect_t *connreq_raw, int status)
{
    std::unique_ptr<uv_connect_t> connreq(connreq_raw);
    if (0 != status)
    {
        fprintf(stderr, "error couldn't connect: %s\n", uv_err_name(status));
        return;
    }

    uv_stream_t *tcphandle = connreq->handle;
    uv_read_start(tcphandle, uv_quick_alloc, on_data_read);

    project::client_t &client = *get_client(tcphandle);

    switch (initiate_tls_handshake(client))
    {
    case project::tls_state_t::WANT_READ: // means OK!
        break;
    case project::tls_state_t::ERROR:
        fprintf(stderr, "error couldn't initiate TLS ClientHello\n");
        uv_close(reinterpret_cast<uv_handle_t *>(tcphandle), on_stream_close);
        break;
    case project::tls_state_t::NOT_HTTPS:
    {
        std::unique_ptr<uv_buf_t> reqbuf;
        prepare_reqbuf(client.hostname.get(), client.path.get(), reqbuf);
        if (int retval = uv_quick_write(tcphandle, reqbuf.get()); 0 != retval)
            uv_close(reinterpret_cast<uv_handle_t *>(tcphandle), on_stream_close);
        else
            reqbuf.release();
        break;
    }
    }
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
        fprintf(stderr, "error couldn't write to file %d: %s\n", fwritereq->file, uv_err_name(fwritereq->result));

        project::prog_t &prog = *get_prog(fwritereq->loop);
        project::client_t &client = *prog.active;
        uv_close(reinterpret_cast<uv_handle_t *>(client.tcphandle.get()), on_stream_close);
        uv_fclose(fwritereq->loop, fwritereq->file);
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
