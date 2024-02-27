#ifndef HTTP_API_H
#define HTTP_API_H

#include "logger_api.h"
#include "server_api.h"
#include "ssl_api.h"
#include <stdint.h>

#define S_GET "GET"
#define REGEX_REQUEST_LINE "([A-Z]+) (.+) (HTTP/1.[0-1])"
#define CRLF "\r\n"
#define MAX_STRING_SIZE 1024
#define MAX_MATCHES 5
#define CRLFCRLF "\r\n\r\n"
#define S_HOST "Host:"
#define HOME_PAGE "index.html"
#define SLASH "/"
#define SPACE " "
#define DQUOTES " "
#define LOWER 1024
#define UPPER 65536
#define REGEX_REQUEST_HDR "([A-Za-z-]+)(: ?)(.+)(\r\n)?"
#define ERR_CLT_UNSUPPORTED_MTHD 0x1
#define ERR_CLT_UNSUPPORTED_HTTP_VERSION 0x2
#define ERR_CLT_CORRUPTED_HEADERS 0x4
#define ERR_CLT_URI_NOT_FOUND 0x8
#define N_200
#define REASON_PHRASE_200 "OK"
#define N_500 500
#define REASON_PHRASE_500 "Internal Server Error"
#define N_505 505
#define REASON_PHRASE_505 "HTTP Version Not Supported"
#define N_400 400
#define REASON_PHRASE_400 "Bad Request"
#define N_404 404
#define REASON_PHRASE_404 "Not found"

typedef int (*write_fn_t)(conn_ctx_t* conn_ctx, void* msg_buf, size_t buf_size,
                          uint8_t options);

typedef struct WriteFnWrapper
{
    int (*write_fn)(conn_ctx_t* conn_ctx, void* msg_buf, size_t buf_size,
                    uint8_t options);
} write_wrap_t;

typedef enum HttpRequestToken
{
    HTTP_REQ_TOKEN_REQUEST_LINE,
    HTTP_REQ_TOKEN_HEADERS,
    HTTP_REQ_TOKEN_BODY,
    COUNT_HTTP_REQ_TOKENS
} http_request_token_t;

typedef struct HttpHeader
{
    char* key;
    char* value;
} http_header_t;

enum HttpResponseHeaderKey
{
    HTTP_RES_HDR_KEY_SERVER = 0,
    HTTP_RES_HDR_KEY_CONTENT_TYPE,
    HTTP_RES_HDR_KEY_CONNECTION,
    HTTP_RES_HDR_KEY_TRANSFER_ENCODING,
    HTTP_RES_HDR_KEEP_ALIVE,
    NUMBER_OF_HTTP_RES_HDR_KEYS
};

enum HttpRequestHeaderKey
{
    HTTP_REQ_HDR_KEY_CONTENT_TYPE = 0,
    HTTP_REQ_HDR_KEY_CONNECTION,
    HTTP_REQ_HDR_KEY_TRANSFER_ENCODING,
    NUMBER_OF_HTTP_REQ_HDR_KEYS
};

typedef struct HttpRequest
{
    char* uri;
    float http_version;
    Method m;
    http_header_t** http_headers;
    int nhttp_headers;
    uint8_t client_err;
} http_request_t;

typedef struct HttpResponse
{
    char* uri;
    uint16_t status_code;
    char* reason_phrase;
    float http_version;
    http_header_t* http_headers;
    int nhttp_headers;
    int (*send)(conn_ctx_t* conn_ctx, struct HttpResponse* http_res,
                write_fn_t write_cb_fn);
} http_response_t;

char* read_mes(conn_ctx_t* conn_ctx);
int write_mes(conn_ctx_t* conn_ctx, void* buf, size_t bufsize, uint8_t options);
http_request_t* http_request_constructor(char* raw, char* default_file,
                                         log_entry_config_t* msg_log_entry);
void http_request_destructor(http_request_t* http_req);
int handle_clt(conn_ctx_t* conn_ctx, char* default_file, char* s_ip, char* c_ip,
               FILE* msg_log_fp, uint8_t* http_srv_options);
http_response_t* http_response_constructor(http_request_t* http_req,
                                           log_entry_config_t* msg_log_entry,
                                           uint8_t* http_srv_options);
void http_response_destructor(http_response_t* http_res);
#endif
