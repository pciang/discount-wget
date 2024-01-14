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

    int parse_url(client_t &client, const std::string &url)
    {
        std::unique_ptr<CURLU> _tmp(curl_url());
        client.curlu.swap(_tmp);

        if (CURLUcode retval = curl_url_set(client.curlu.get(), CURLUPART_URL, opts.url.c_str(), CURLU_GUESS_SCHEME); CURLUE_OK != retval)
            return -1;

        curl_url_get(client.curlu.get(), CURLUPART_SCHEME, client.scheme, 0);
        curl_url_get(client.curlu.get(), CURLUPART_HOST, client.hostname, 0);
        curl_url_get(client.curlu.get(), CURLUPART_PORT, client.port, CURLU_DEFAULT_PORT);
        curl_url_get(client.curlu.get(), CURLUPART_PATH, client.path, 0);

        return 0;
    }

    int init_client(client_tpp &p_client, llhttp_settings_t &settings)
    {
        {
            client_tpp _tmp(new (reinterpret_cast<client_t *>(malloc(sizeof(client_t)))) client_t);
            p_client.swap(_tmp);
        }

        client_t &client = *p_client;
        if (int retval = parse_url(client, opts.url); 0 != retval)
        {
            fprintf(stderr, "error couldn't parse URL\n");
            return retval;
        }

        client.usehttps = false;
        if (int retval = std::string("https").compare(client.scheme.get()); 0 == retval)
            client.usehttps = true;

        if (int retval = init_httpresp_parser(client, settings); 0 != retval)
            return retval;

        client.loop = uv_default_loop();
        uv_loop_set_data(client.loop, p_client.get());

        // init openssl
        SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
        SSL_CTX_set_default_verify_paths(ssl_ctx);
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_connect_state(ssl); // I am a client
        SSL_set_bio(ssl, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
        SSL_set1_host(ssl, client.hostname.get());

        {
            std::unique_ptr<SSL> _tmp(ssl);
            client.tls.swap(_tmp);
        }

        return 0;
    }

    int init_prog(project::prog_t &prog)
    {
        prog.loop = uv_default_loop();
        init_httpresp_parser_settings(prog.settings);
        return 0;
    }
};

int run_phase_one(project::client_t &client)
{
    client.outfiled = 0;
    client.resolved = NULL;

    std::unique_ptr<uv_fs_t> fsreq(reinterpret_cast<uv_fs_t *>(malloc(sizeof(uv_fs_t))));
    if (int retval = uv_fs_open(client.loop, fsreq.get(), project::opts.outfilename.c_str(), UV_FS_O_CREAT | UV_FS_O_RDWR, S_IRWXU | S_IRGRP | S_IROTH, on_fs_open))
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
    if (int retval = uv_getaddrinfo(client.loop, getaddreq.get(), on_getaddrinfo, client.hostname.get(), client.port.get(), &hint))
    {
        fprintf(stderr, "error attempting to resolve %s with message: %s\n", client.hostname.get(), uv_err_name(retval));
        return retval;
    }
    else
        getaddreq.release();

    return uv_run(client.loop, UV_RUN_DEFAULT);
}

bool check_phase_one(project::client_t &client)
{
    return 0 < client.outfiled && NULL != client.resolved;
}

int run_phase_two(project::client_t &client)
{
    std::unique_ptr<uv_tcp_t> tcphandle(reinterpret_cast<uv_tcp_t *>(malloc(sizeof(uv_tcp_t))));
    if (int retval = uv_tcp_init(client.loop, tcphandle.get()); 0 != retval)
    {
        fprintf(stderr, "error couldn't init tcp: %s\n", uv_err_name(retval));
        return retval;
    }
    else
        client.tcphandle.swap(tcphandle);

    std::unique_ptr<uv_connect_t> connreq(reinterpret_cast<uv_connect_t *>(malloc(sizeof(uv_connect_t))));
    if (int retval = uv_tcp_connect(connreq.get(), client.tcphandle.get(), client.resolved->ai_addr, on_tcp_connect); 0 != retval)
    {
        fprintf(stderr, "error couldn't initiate a tcp conn: %s\n", uv_err_name(retval));
        return retval;
    }
    else
        connreq.release();

    return uv_run(client.loop, UV_RUN_DEFAULT);
}

project::tls_state_t initiate_tls_handshake(const project::client_t &client)
{
    if (!client.usehttps)
        return project::tls_state_t::NOT_HTTPS;

    SSL_connect(client.tls.get());

    std::unique_ptr<uv_buf_t> uvbuf;
    if (project::flush_wbio_t retval = flush_wbio(client.tls.get(), uvbuf); project::flush_wbio_t::OK != retval)
    {
        fprintf(stderr, "error nothing flushable in wbio (shouldn't happen)\n");
        return project::tls_state_t::ERROR;
    }

    if (int retval = uv_quick_write(reinterpret_cast<uv_stream_t *>(client.tcphandle.get()), uvbuf.get()); 0 != retval)
    {
        fprintf(stderr, "error couldn't initiate write %p: %s\n", reinterpret_cast<void *>(client.tcphandle.get()), uv_err_name(retval));
        uv_close(reinterpret_cast<uv_handle_t *>(client.tcphandle.get()), on_stream_close);
        return project::tls_state_t::ERROR;
    }
    else
        uvbuf.release();

    return project::tls_state_t::WANT_READ;
}

project::tls_state_t handle_tls_handshake(const project::client_t &client, const uv_buf_t *readbuf, ssize_t nread, std::unique_ptr<uv_buf_t> &writebuf)
{
    if (SSL_is_init_finished(client.tls.get()))
        return project::tls_state_t::OK;

    flush_uv_readbuf(client.tls.get(), readbuf, nread);
    SSL_do_handshake(client.tls.get());

    if (project::flush_wbio_t retval = flush_wbio(client.tls.get(), writebuf); project::flush_wbio_t::OK != retval)
    {
        fprintf(stderr, "warning nothing in wbio to flush during handshake\n");
        return project::tls_state_t::WANT_READ;
    }

    if (SSL_is_init_finished(client.tls.get()))
        return project::tls_state_t::OK_FINISH;

    return project::tls_state_t::HAS_PAYLOAD;
}

int try_send_httpreq(SSL *tls, uv_stream_t *tcphandle)
{
    if (!SSL_is_init_finished(tls))
        return -1;

    project::client_t &client = *get_active_client(tcphandle->loop);

    std::string httpreq = project::prepare_httpreq(client.hostname.get(), client.path.get());
    SSL_write(tls, httpreq.c_str(), httpreq.length());

    std::unique_ptr<uv_buf_t> writebuf;
    if (project::flush_wbio_t retval = flush_wbio(tls, writebuf); project::flush_wbio_t::OK != retval)
        return -1;

    if (int retval = uv_quick_write(tcphandle, writebuf.get()); 0 != retval)
    {
        fprintf(stderr, "error while trying to send http req: %s\n", uv_err_name(retval));
        return -1;
    }
    else
        writebuf.release();

    return 0;
}

void on_data_read(uv_stream_t *tcphandle, ssize_t nread, const uv_buf_t *readbuf)
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
            uv_shutdown(shutreq, tcphandle, on_shutdown);
            break;
        }
        default:
            uv_close(reinterpret_cast<uv_handle_t *>(tcphandle), on_stream_close);
            break;
        }
        return;
    }

    project::client_t &client = *get_active_client(tcphandle->loop);
    if (client.usehttps)
    {
        std::unique_ptr<uv_buf_t> writebuf;

        project::tls_state_t tls_state = handle_tls_handshake(client, readbuf, nread, writebuf);
        switch (tls_state)
        {
        case project::tls_state_t::OK: // essentially, TLS handshake is finished
            break;
        case project::tls_state_t::HAS_PAYLOAD:
        case project::tls_state_t::OK_FINISH:
        {
            if (int retval = uv_quick_write(tcphandle, writebuf.get()); 0 != retval)
            {
                fprintf(stderr, "error couldn't initiate write %p: %s\n", reinterpret_cast<void *>(tcphandle), uv_err_name(retval));
                uv_close(reinterpret_cast<uv_handle_t *>(tcphandle), on_stream_close);
            }
            else
                writebuf.release();

            if (project::tls_state_t::OK_FINISH == tls_state)
                try_send_httpreq(client.tls.get(), tcphandle);
            return;
        }
        case project::tls_state_t::WANT_READ:
            return;
        }

        flush_uv_readbuf(client.tls.get(), readbuf, nread);

        std::unique_ptr<uv_buf_t> plainbuf;
        for (project::flush_wbio_t code = ssl_quick_read(client.tls.get(), plainbuf); project::flush_wbio_t::OK == code;)
        {
            if (llhttp_errno_t retval = llhttp_execute(&client.composite.parser, plainbuf->base, plainbuf->len); HPE_OK != retval)
            {
                fprintf(stderr, "error parsing HTTP response: %s\n", llhttp_errno_name(retval));
                uv_close(reinterpret_cast<uv_handle_t *>(tcphandle), on_stream_close);
                break;
            }
            code = ssl_quick_read(client.tls.get(), plainbuf);
        }
    }
    else
    {
        if (llhttp_errno_t retval = llhttp_execute(&client.composite.parser, readbuf->base, nread); HPE_OK != retval)
        {
            fprintf(stderr, "error parsing HTTP response: %s\n", llhttp_errno_name(retval));
            uv_close(reinterpret_cast<uv_handle_t *>(tcphandle), on_stream_close);
        }
    }
}

int on_httpresp_body(llhttp_t *parser, const char *at, size_t length)
{
    project::client_t &client = *get_active_client(parser);

    std::unique_ptr<uv_buf_t> fwritebuf;
    prepare_uvbuf(at, length, fwritebuf);
    if (int retval = uv_writeto(client.loop, client.outfiled, client.outfiled_offset, fwritebuf.get()); 0 != retval)
    {
        fprintf(stderr, "error writing into output file: %s\n", uv_err_name(retval));
        return -1;
    }
    else
        fwritebuf.release();

    client.outfiled_offset += length;
    return 0;
}

#endif
