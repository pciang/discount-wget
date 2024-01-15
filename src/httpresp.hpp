#ifndef DISCOUNT_WGET_HTTPRESP_HPP
#define DISCOUNT_WGET_HTTPRESP_HPP

#include "common.hpp"

project::composite_parser_t *get_composite(llhttp_t *parser)
{
    return reinterpret_cast<project::composite_parser_t *>(parser);
}

project::prog_t *get_prog(llhttp_t *parser)
{
    return reinterpret_cast<project::prog_t *>(uv_loop_get_data(get_composite(parser)->client->tcphandle->loop));
}

int on_header_field_or_value(llhttp_t *parser, const char *at, size_t length)
{
    get_composite(parser)->partial.append(at, at + length);
    return 0;
}

int on_header_field_complete(llhttp_t *parser)
{
    project::composite_parser_t &composite = *get_composite(parser);
    auto retval = composite.headers.emplace(project::header_t::value_type(std::move(composite.partial), ""));
    composite.pheader = retval.first;
    return 0;
}

int on_header_value_complete(llhttp_t *parser)
{
    project::composite_parser_t &composite = *get_composite(parser);
    composite.pheader->second.swap(composite.partial);
    return 0;
}

int on_http_status(llhttp_t *parser, const char *at, size_t length)
{
    get_composite(parser)->partial.append(at, at + length);
    return 0;
}

int on_http_status_complete(llhttp_t *parser)
{
    project::composite_parser_t &composite = *get_composite(parser);
    composite.status = std::stoi(std::move(composite.partial));
    return 0;
}

int on_httpresp_body(llhttp_t *, const char *, size_t);

int init_httpresp_parser_settings(llhttp_settings_t &settings)
{
    llhttp_settings_init(&settings);
    settings.on_status = on_http_status;
    settings.on_status_complete = on_http_status_complete;
    settings.on_header_field = on_header_field_or_value;
    settings.on_header_value = on_header_field_or_value;
    settings.on_header_field_complete = on_header_field_complete;
    settings.on_header_value_complete = on_header_value_complete;
    settings.on_body = on_httpresp_body;
    return 0;
}

int init_httpresp_parser(project::client_t &client, llhttp_settings_t &settings)
{
    project::composite_parser_t &composite = client.composite;
    composite.pheader = composite.headers.begin();
    llhttp_init(&composite.parser, HTTP_RESPONSE, &settings);
    composite.client = &client;
    return 0;
}

#endif
