// Jsonrpc (client) implementation
// Copyright (C) 2022 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.
#include "jsonrpc.h"

#include <assert.h>
#include <json-c/json.h>
#include <sys/select.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include <string.h>

using namespace std;

#define MAX_HEADER_LINELENGTH 256
/* Store a header line into s_line, and return true if the line is NOT the final line ('\r\n')
 * The header consists of lines of the form  'Field: Value\r\n'
 * See https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#headerPart
 */
bool jsonrpc_connection::_read_header_line(string &s_line)
{
    char line[MAX_HEADER_LINELENGTH];
    int c;
    for (c = 0;
         c < MAX_HEADER_LINELENGTH && ((c < 2) || (line[c - 2] != '\r' && line[c - 1] != '\n'));
         c++)
    {
        if (1 != read(IN_FILNO, line + c, 1))
            throw jsonrpc_error(LSPErrCode.InternalError, "In file descriptor closed unexpectedly");
    }
    line[c - 1] = '\0'; // Don't bother returning the "\r\n";
    s_line = line;

    return c > 2 && c < MAX_HEADER_LINELENGTH;
}

void jsonrpc_connection::_read_header(jsonrpc_header &h)
{
    string line;
    while (_read_header_line(line))
    {
        // These are the only 2 supported header fields
        const char *field1 = "Content-Length: ";
        const char *field2 = "Content-Type: ";

        if (line.substr(0, strlen(field1)) == field1)
        {
            h.content_length = stoi(line.substr(strlen(field1)));
        }
        else if (line.substr(0, strlen(field2)) == field2)
        {
            // There is only one supported LSP content type: "application/vscode-jsonrpc; utf-8"
            // FIXME: Just ignore it or be strict?
        }
    };
}

/* Block until a request arrives
 */
void jsonrpc_connection::wait_for_request()
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(IN_FILNO, &rfds);
    select(1, &rfds, NULL, NULL, NULL);
}

jsonrpc_request *jsonrpc_connection::get_request()
{
    jsonrpc_header h;
    _read_header(h);

    char *jsonrpc_payload = (char *)malloc(h.content_length + 1);
    if ((ssize_t)h.content_length != read(IN_FILNO, jsonrpc_payload, h.content_length))
        throw jsonrpc_error(LSPErrCode.InternalError, "The was an issue reading the request payload");
    jsonrpc_payload[h.content_length] = '\0';

    if (verbose > 2)
    {
        cerr << "Content-Length: " << to_string(h.content_length) << endl;
        cerr << "Content-Type: " << h.content_type << endl;
        cerr << jsonrpc_payload << endl;
    }

    jsonrpc_request *req = new jsonrpc_request(jsonrpc_payload);
    free(jsonrpc_payload);

    return req;
}

void jsonrpc_connection::_write_header_line(string field, string value, bool final_line)
{
    string hline = field + ": " + value + "\r\n" + (final_line ? "\r\n" : "");
    if ((ssize_t)hline.size() != write(OUT_FILENO, hline.c_str(), hline.size()))
        throw jsonrpc_error(LSPErrCode.InternalError, "The was an issue writing the response header");
}

void jsonrpc_connection::send_response(jsonrpc_request *request, jsonrpc_response *response)
{
    jsonrpc_header h;
    json_object *body = response->to_json(request);
    assert(response->result_or_error_set);

    const char *body_str = json_object_to_json_string_length(body, JSON_C_TO_STRING_SPACED, &(h.content_length));
    _write_header_line("Content-Length", to_string(h.content_length));
    _write_header_line("Content-Type", h.content_type, /*final_line = */ true);
    if ((ssize_t)h.content_length != write(OUT_FILENO, body_str, h.content_length))
        throw jsonrpc_error(LSPErrCode.InternalError, "The was an issue writing the response payload");
}