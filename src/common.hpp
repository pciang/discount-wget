#ifndef DISCOUNT_WGET_COMMON_HPP
#define DISCOUNT_WGET_COMMON_HPP

#include <map>
#include <string>
#include <memory>

#include "uv.h"
#include "llhttp.h"
#include "curl/curl.h"
#include "openssl/ssl.h"

namespace project
{
    const char *TEMPLATE_GET = "GET {path} HTTP/1.1\r\n"
                               "Host: {host}\r\n"
                               "User-Agent: discount-wget\r\n"
                               "Accept: */*\r\n"
                               "Accept-Encoding: identity\r\n"
                               "Connection: close\r\n"
                               "\r\n";

    const char *HELPSTR =
        "Usage: discount-wget -o output_file URL\n"
        "  -h    Displays help\n"
        "  -o    Output file name (e.g.: ~/Downloads/myfile.txt)\n"
        "\n"
        "Positional argument:\n"
        "  URL   The download URL\n";

    typedef std::map<std::string, std::string> header_t;

    typedef header_t::iterator pheader_t;

    struct composite_parser_t;
    struct client_t;

    struct composite_parser_t
    {
        llhttp_t parser;
        llhttp_settings_t settings;
        std::string partial;
        int status;
        header_t headers;
        pheader_t pheader;
        client_t *client;
    };

    struct opts_t
    {
        std::string
            url,
            outfilename;
    } opts;

    struct client_t
    {
        std::unique_ptr<uv_tcp_t> tcphandle;
        std::unique_ptr<SSL> tls;
        std::unique_ptr<CURLU> curlu;
        std::unique_ptr<char> scheme,
            hostname,
            port,
            path;
        std::unique_ptr<addrinfo> resolved;
        composite_parser_t composite;
        bool usehttps;
    };

    struct prog_t
    {
        uv_loop_t *loop;
        client_t *active;
        ssize_t outfiled;
        int64_t outfiled_offset;
        llhttp_settings_t settings;
    };

    enum class tls_state_t : int
    {
        OK = 0,
        WANT_READ,
        HAS_PAYLOAD,
        OK_FINISH,
        NOT_HTTPS,
        ERROR
    };

    std::string prepare_httpreq(const char *hostname, const char *path)
    {
        std::string getreq = TEMPLATE_GET;
        getreq.replace(getreq.find("{host}"), 6, hostname)
            .replace(getreq.find("{path}"), 6, path);
        return getreq;
    }

    void uv_free(uv_buf_t *uvbuf)
    {
        free(uvbuf->base);
        free(uvbuf);
    }

    CURLUcode curl_url_get(CURLU *handle, CURLUPart what, std::unique_ptr<char> &part, unsigned int flags)
    {
        char *part_raw;
        CURLUcode retval = ::curl_url_get(handle, what, &part_raw, flags);
        std::unique_ptr<char> _tmp(part_raw);
        part.swap(_tmp);
        return retval;
    }

    int init_prog(project::prog_t &);
};

template <>
void std::default_delete<uv_buf_t>::operator()(uv_buf_t *uvbuf) const
{
    free(uvbuf->base);
    free(uvbuf);
}

template <>
void std::default_delete<uv_fs_t>::operator()(uv_fs_t *fsreq) const
{
    free(fsreq);
}

template <>
void std::default_delete<uv_tcp_t>::operator()(uv_tcp_t *tcphandle) const
{
    free(tcphandle);
}

template <>
void std::default_delete<uv_getaddrinfo_t>::operator()(uv_getaddrinfo_t *getaddreq) const
{
    free(getaddreq);
}

template <>
void std::default_delete<uv_connect_t>::operator()(uv_connect_t *connreq) const
{
    free(connreq);
}

template <>
void std::default_delete<CURLU>::operator()(CURLU *curl) const
{
    curl_free(curl);
}

template <>
void std::default_delete<SSL>::operator()(SSL *ssl) const
{
    SSL_free(ssl);
}

#endif
