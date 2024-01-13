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
    struct prog_t;

    struct composite_parser_t
    {
        llhttp_t parser;
        llhttp_settings_t settings;
        header_t headers;
        pheader_t pheader;
        std::string partial;
        prog_t *prog;
    };

    struct opts_t
    {
        std::string
            url,
            outfilename;
    } opts;

    struct prog_t
    {
        uv_loop_t *loop;
        uv_tcp_t *client;
        SSL *tls;
        CURLU *curlh;
        char *scheme,
            *hostname,
            *port,
            *path;
        addrinfo *resolved;
        composite_parser_t composite;
        ssize_t outfiled;
        int64_t outfiled_offset;
        bool usehttps;
    };

    typedef std::unique_ptr<prog_t> prog_tpp;

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

        return std::move(getreq.replace(getreq.find("{host}"), 6, hostname)
                             .replace(getreq.find("{path}"), 6, path));
    }

    void uv_free(uv_buf_t *uvbuf)
    {
        free(uvbuf->base);
        free(uvbuf);
    }

    int init_prog(prog_tpp &);
};

template <>
void std::default_delete<uv_buf_t>::operator()(uv_buf_t *uvbuf) const
{
    free(uvbuf->base);
    free(uvbuf);
}

#endif
