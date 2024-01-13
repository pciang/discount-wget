#ifndef DISCOUT_WGET_MAIN_HPP
#define DISCOUT_WGET_MAIN_HPP

#include "getopt.h"

#include "tls.hpp"
#include "async.hpp"
#include "httpresp.hpp"

namespace project
{
    int parse_opts(int argc, char *argv[])
    {
        int retval;

        do
        {
            retval = getopt(argc, argv, "ho:");

            switch (retval)
            {
            case 'o':
                opts.outfilename = optarg;
                break;
            case '?':
            case 'h':
                fprintf(stderr, HELPSTR);
                break;
            }
        } while (-1 != retval && '?' != retval);

        if (optind < argc)
            opts.url = argv[optind];

        if (opts.url.empty() || opts.outfilename.empty())
        {
            fprintf(stderr, HELPSTR);

            return -1;
        }

        return 0;
    }

    int parse_url(prog_t &prog)
    {
        prog.curlh = curl_url();

        if (CURLUcode retval = curl_url_set(prog.curlh, CURLUPART_URL, opts.url.c_str(), CURLU_GUESS_SCHEME); CURLUE_OK != retval)
            return -1;

        curl_url_get(prog.curlh, CURLUPART_SCHEME, &prog.scheme, 0);
        curl_url_get(prog.curlh, CURLUPART_HOST, &prog.hostname, 0);
        curl_url_get(prog.curlh, CURLUPART_PORT, &prog.port, CURLU_DEFAULT_PORT);
        curl_url_get(prog.curlh, CURLUPART_PATH, &prog.path, 0);

        return 0;
    }

    int init_prog(prog_tpp &prog)
    {
        prog_tpp temp(new (reinterpret_cast<prog_t *>(malloc(sizeof(prog_t)))) prog_t);
        prog.swap(temp);

        if (int retval = parse_url(*prog); 0 != retval)
        {
            fprintf(stderr, "error couldn't parse URL\n");
            return retval;
        }

        prog->usehttps = false;
        if (int retval = std::string("https").compare(prog->scheme); 0 == retval)
            prog->usehttps = true;

        if (int retval = init_httpresp_parser(*prog); 0 != retval)
            return retval;

        prog->loop = uv_default_loop();
        uv_loop_set_data(prog->loop, prog.get());

        // init openssl
        SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
        SSL_CTX_set_default_verify_paths(ssl_ctx);
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_connect_state(ssl); // I am a client
        SSL_set_bio(ssl, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
        SSL_set1_host(ssl, prog->hostname);

        prog->tls = ssl;

        return 0;
    }
};

int run_phase_one(project::prog_t &prog)
{
    prog.outfiled = 0;
    prog.resolved = NULL;

    std::unique_ptr<uv_fs_t> fsreq(reinterpret_cast<uv_fs_t *>(malloc(sizeof(uv_fs_t))));
    if (int retval = uv_fs_open(prog.loop, fsreq.get(), project::opts.outfilename.c_str(), UV_FS_O_CREAT | UV_FS_O_RDWR, S_IRWXU | S_IRGRP | S_IROTH, on_fs_open))
    {
        fprintf(stderr, "error attempting to write into the file %s with message: %s\n", project::opts.outfilename.c_str(), uv_err_name(retval));
        return retval;
    }
    else
        fsreq.release();

    addrinfo hint;
    memset(&hint, 0, sizeof(addrinfo));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;

    std::unique_ptr<uv_getaddrinfo_t> getaddreq(reinterpret_cast<uv_getaddrinfo_t *>(malloc(sizeof(uv_getaddrinfo_t))));
    if (int retval = uv_getaddrinfo(prog.loop, getaddreq.get(), on_getaddrinfo, prog.hostname, prog.port, &hint))
    {
        fprintf(stderr, "error attempting to resolve %s with message: %s\n", prog.hostname, uv_err_name(retval));
        return retval;
    }
    else
        getaddreq.release();

    return uv_run(prog.loop, UV_RUN_DEFAULT);
}

bool check_phase_one(project::prog_t &prog)
{
    return 0 < prog.outfiled && NULL != prog.resolved;
}

int run_phase_two(project::prog_t &prog)
{
    std::unique_ptr<uv_tcp_t> client(reinterpret_cast<uv_tcp_t *>(malloc(sizeof(uv_tcp_t))));
    if (int retval = uv_tcp_init(prog.loop, client.get()); 0 != retval)
    {
        fprintf(stderr, "error couldn't init tcp: %s\n", uv_err_name(retval));
        return retval;
    }
    else
        prog.client = client.release();

    std::unique_ptr<uv_connect_t> connreq(reinterpret_cast<uv_connect_t *>(malloc(sizeof(uv_connect_t))));
    if (int retval = uv_tcp_connect(connreq.get(), prog.client, prog.resolved->ai_addr, on_tcp_connect); 0 != retval)
    {
        fprintf(stderr, "error couldn't initiate a tcp conn: %s\n", uv_err_name(retval));
        return retval;
    }
    else
        connreq.release();

    return uv_run(prog.loop, UV_RUN_DEFAULT);
}

project::tls_state_t initiate_tls_handshake(const project::prog_t &prog)
{
    if (!prog.usehttps)
        return project::tls_state_t::NOT_HTTPS;

    SSL_connect(prog.tls);

    std::unique_ptr<uv_buf_t> uvbuf;
    if (project::flush_wbio_t retval = flush_wbio(prog.tls, uvbuf); project::flush_wbio_t::OK != retval)
    {
        fprintf(stderr, "error nothing flushable in wbio (shouldn't happen)\n");
        return project::tls_state_t::ERROR;
    }

    if (int retval = uv_quick_write(reinterpret_cast<uv_stream_t *>(prog.client), uvbuf.get()); 0 != retval)
    {
        fprintf(stderr, "error couldn't initiate write %p: %s\n", reinterpret_cast<void *>(prog.client), uv_err_name(retval));
        uv_close(reinterpret_cast<uv_handle_t *>(prog.client), on_stream_close);
        return project::tls_state_t::ERROR;
    }
    else
        uvbuf.release();

    return project::tls_state_t::WANT_READ;
}

project::tls_state_t handle_tls_handshake(const project::prog_t &prog, const uv_buf_t *readbuf, ssize_t nread, std::unique_ptr<uv_buf_t> &writebuf)
{
    if (SSL_is_init_finished(prog.tls))
        return project::tls_state_t::OK;

    flush_uv_readbuf(prog.tls, readbuf, nread);
    SSL_do_handshake(prog.tls);

    if (project::flush_wbio_t retval = flush_wbio(prog.tls, writebuf); project::flush_wbio_t::OK != retval)
    {
        fprintf(stderr, "warning nothing in wbio to flush during handshake\n");
        return project::tls_state_t::WANT_READ;
    }

    if (SSL_is_init_finished(prog.tls))
        return project::tls_state_t::OK_FINISH;

    return project::tls_state_t::HAS_PAYLOAD;
}

int try_send_httpreq(SSL *tls, uv_stream_t *stream)
{
    if (!SSL_is_init_finished(tls))
        return -1;

    const project::prog_t *prog = get_prog(stream->loop);

    std::string httpreq = project::prepare_httpreq(prog->hostname, prog->path);
    SSL_write(tls, httpreq.c_str(), httpreq.length());

    std::unique_ptr<uv_buf_t> writebuf;
    if (project::flush_wbio_t retval = flush_wbio(tls, writebuf); project::flush_wbio_t::OK != retval)
        return -1;

    if (int retval = uv_quick_write(stream, writebuf.get()); 0 != retval)
    {
        fprintf(stderr, "error while trying to send http req: %s\n", uv_err_name(retval));
        return -1;
    }
    else
        writebuf.release();

    return 0;
}

void on_data_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *readbuf)
{
    std::unique_ptr<char> _readbuf_base(readbuf->base);

    if (0 >= nread)
    {
        switch (nread)
        {
        case 0:
        case UV_ECANCELED:
            break;
        case UV_EOF:
        {
            uv_shutdown_t *shutreq = reinterpret_cast<uv_shutdown_t *>(malloc(sizeof(uv_shutdown_t)));
            uv_shutdown(shutreq, stream, on_shutdown);
            break;
        }
        default:
            uv_close(reinterpret_cast<uv_handle_t *>(stream), on_stream_close);
            break;
        }
        return;
    }

    const project::prog_t *prog = get_prog(stream->loop);
    if (prog->usehttps)
    {
        std::unique_ptr<uv_buf_t> writebuf;

        project::tls_state_t tls_state = handle_tls_handshake(*prog, readbuf, nread, writebuf);
        switch (tls_state)
        {
        case project::tls_state_t::OK: // essentially, TLS handshake is finished
            break;
        case project::tls_state_t::HAS_PAYLOAD:
        case project::tls_state_t::OK_FINISH:
        {
            if (int retval = uv_quick_write(stream, writebuf.get()); 0 != retval)
            {
                fprintf(stderr, "error couldn't initiate write %p: %s\n", reinterpret_cast<void *>(stream), uv_err_name(retval));
                uv_close(reinterpret_cast<uv_handle_t *>(stream), on_stream_close);
            }
            else
                writebuf.release();

            if (project::tls_state_t::OK_FINISH == tls_state)
                try_send_httpreq(prog->tls, stream);
            return;
        }
        case project::tls_state_t::WANT_READ:
            return;
        }

        flush_uv_readbuf(prog->tls, readbuf, nread);

        std::unique_ptr<uv_buf_t> plainbuf;
        for (project::flush_wbio_t code = ssl_quick_read(prog->tls, plainbuf); project::flush_wbio_t::OK == code;)
        {
            if (llhttp_errno_t retval = llhttp_execute(&const_cast<project::prog_t *>(prog)->composite.parser, plainbuf->base, plainbuf->len); HPE_OK != retval)
            {
                fprintf(stderr, "error parsing HTTP response: %s\n", llhttp_errno_name(retval));
                uv_close(reinterpret_cast<uv_handle_t *>(stream), on_stream_close);
                break;
            }
            code = ssl_quick_read(prog->tls, plainbuf);
        }
    }
    else
    {
        if (llhttp_errno_t retval = llhttp_execute(&const_cast<project::prog_t *>(prog)->composite.parser, readbuf->base, nread); HPE_OK != retval)
        {
            fprintf(stderr, "error parsing HTTP response: %s\n", llhttp_errno_name(retval));
            uv_close(reinterpret_cast<uv_handle_t *>(stream), on_stream_close);
        }
    }
}

int on_httpresp_body(llhttp_t *parser, const char *at, size_t length)
{
    const project::prog_t *prog = get_prog(parser);

    std::unique_ptr<uv_buf_t> fwritebuf;
    prepare_uvbuf(at, length, fwritebuf);
    if (int retval = uv_writeto(prog->loop, prog->outfiled, prog->outfiled_offset, fwritebuf.get()); 0 != retval)
    {
        fprintf(stderr, "error writing into output file: %s\n", uv_err_name(retval));
        return -1;
    }
    else
        fwritebuf.release();

    const_cast<project::prog_t *>(prog)->outfiled_offset += length;
    return 0;
}

#endif
