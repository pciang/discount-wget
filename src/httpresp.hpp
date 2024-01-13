#ifndef DISCOUNT_WGET_HTTPRESP_HPP
#define DISCOUNT_WGET_HTTPRESP_HPP

#include "common.hpp"

project::composite_parser_t *get_composite(llhttp_t *parser)
{
    return reinterpret_cast<project::composite_parser_t *>(parser);
}

const project::prog_t *get_prog(llhttp_t *parser)
{
    return get_composite(parser)->prog;
}

int on_header_field_or_value(llhttp_t *parser, const char *at, size_t length)
{
    get_composite(parser)->partial.append(at, at + length);
    return 0;
}

int on_header_field_complete(llhttp_t *parser)
{
    project::composite_parser_t *composite = get_composite(parser);
    auto retval = composite->headers.emplace(project::header_t::value_type(std::move(composite->partial), ""));
    composite->pheader = retval.first;
    return 0;
}

int on_header_value_complete(llhttp_t *parser)
{
    project::composite_parser_t *composite = get_composite(parser);
    composite->pheader->second = std::move(composite->partial);
    return 0;
}

int on_httpresp_body(llhttp_t *, const char *, size_t);

int init_httpresp_parser(project::prog_t &prog)
{
    project::composite_parser_t &composite = prog.composite;
    composite.pheader = composite.headers.begin();

    llhttp_settings_init(&composite.settings);
    composite.settings.on_header_field = on_header_field_or_value;
    composite.settings.on_header_value = on_header_field_or_value;
    composite.settings.on_header_field_complete = on_header_field_complete;
    composite.settings.on_header_value_complete = on_header_value_complete;
    composite.settings.on_body = on_httpresp_body;
    llhttp_init(&composite.parser, HTTP_RESPONSE, &composite.settings);

    composite.prog = &prog;
    return 0;
}

#endif
