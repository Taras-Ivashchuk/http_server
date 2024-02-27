#include "http_api.h"
#include "config_api.h"
#include "logger_api.h"
#include "server_api.h"
#include "ssl_api.h"
#include <ctype.h>
#include <errno.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern uint8_t g_is_https;

static char* http_request_headers_keys[NUMBER_OF_HTTP_REQ_HDR_KEYS] = {
    [HTTP_REQ_HDR_KEY_CONTENT_TYPE] = "Content-Type",
    [HTTP_REQ_HDR_KEY_CONNECTION] = "Connection",
    [HTTP_REQ_HDR_KEY_TRANSFER_ENCODING] = "Transfer-Encoding"};

static http_header_t http_response_headers_data[NUMBER_OF_HTTP_RES_HDR_KEYS] = {
    [HTTP_RES_HDR_KEY_SERVER] = {.key = "Server", .value = "webserver-c"},
    [HTTP_RES_HDR_KEY_CONTENT_TYPE] = {.key = "Content-Type",
                                       .value = "text/html"},
    [HTTP_RES_HDR_KEY_CONNECTION] = {.key = "Connection",
                                     .value = "keep-alive"},
    [HTTP_RES_HDR_KEY_TRANSFER_ENCODING] = {.key = "Transfer-Encoding",
                                            .value = "chunked"},
    [HTTP_RES_HDR_KEEP_ALIVE] = {.key = "Keep-Alive",
                                 .value = "timeout=10, max=1000"}};
// private prototypes

int get_regex_matches(const char* str, char* regex, char** matches);
char* extract_request_token(char* raw, http_request_token_t http_req_token);
void free_match_regex(char** matches, int nmatches);
int parse_uri(char* uri, http_request_t* http_req, char* default_file,
              log_entry_config_t* msg_log_entry);
int parse_http_request_line(http_request_t* http_req, char* http_req_line,
                            char* default_file,
                            log_entry_config_t* msg_log_entry);
int parse_http_headers(http_request_t* http_req, char* extr_headers);
int parse_http_request(http_request_t* http_req, char* extr_status_line,
                       char* extr_http_headers, char* extr_http_body,
                       char* default_file, log_entry_config_t* msg_log_entry);
int construct_http_response_status_line(http_request_t* http_req,
                                        http_response_t* http_res,
                                        log_entry_config_t* msg_log_entry);
char* serialize_http_response_status_line(http_response_t* http_res);
int construct_http_response_headers(http_request_t* http_req,
                                    http_response_t* http_res,
                                    uint8_t* http_srv_options);
char* serialize_http_response_headers(http_response_t* http_res);
int send_http_response_fn(conn_ctx_t* conn_ctx, http_response_t* http_res,
                          write_fn_t send_body_fn);
http_header_t* http_header_constructor(char* key, char* value);
void http_header_destructor(http_header_t* http_hdr);
void chunk_constructor(char* msg, size_t msgsize, char* chunk_buf,
                       size_t chunk_bufsize);
http_header_t*
get_http_response_header_data(enum HttpResponseHeaderKey http_res_hdr_key,
                              http_header_t* http_response_headers_data);

http_header_t*
get_http_response_header(enum HttpResponseHeaderKey http_res_hdr_key,
                         http_response_t* http_res);
http_header_t*
get_http_request_header(enum HttpRequestHeaderKey http_header_request_key,
                        http_request_t* http_req);
int write_chunked_mes(conn_ctx_t* conn_ctx, void* mes_buf, size_t mes_buf_size,
                      uint8_t is_last_chunk);
uint8_t is_http_res_hdr_supported(enum HttpResponseHeaderKey http_res_hdr_key,
                                  enum HttpRequestHeaderKey http_req_hdr_key,
                                  http_request_t* http_req);
void to_lower(char* src, char* dst);

char* read_mes(conn_ctx_t* conn_ctx)
{
    unsigned long bytes_to_read = 1024;
    int allocated = bytes_to_read;
    int increase = bytes_to_read;

    char* msg = (char*)malloc(allocated);
    char* new_msg = NULL;

    if (msg == NULL)
    {
        print_debug(ERROR, "malloc msg: read_msg %s\n", strerror(errno));
        goto exit;
    }

    int nbytes = 0;

    while ((nbytes = recv(conn_ctx->connfd, msg + nbytes, bytes_to_read, 0)))
    {

        if (nbytes < 0)
        {
            print_debug(INFO, "recv < 0 errno #%i\n", errno);
            print_debug(INFO, "error %s\n", strerror(errno));
            return NULL;
        }

        allocated = allocated + increase;
        new_msg = (char*)realloc(msg, allocated);

        if (new_msg == NULL)
        {
            perror("realloc :read_msg");
            goto exit_realloc;
        }

        if (new_msg != msg)
        {
            msg = new_msg;
        }

        if (nbytes < (int)bytes_to_read)
        {
            break;
        }
    }

    new_msg = (char*)realloc(msg, strlen(msg) + 1);
    if (new_msg == NULL)
    {
        perror("realloc : read_msg");
        goto exit_realloc;
    }

    if (new_msg != msg)
    {
        msg = new_msg;
    }

    msg[strlen(msg)] = '\0';

    return msg;

exit:
    return NULL;

exit_calloc:
    if (msg != NULL)
    {
        free(msg);
    }
    goto exit;

exit_poll:
    goto exit_calloc;

exit_realloc:
    goto exit_poll;
}

int write_mes(conn_ctx_t* conn_ctx, void* buf, size_t bufsize, uint8_t options)
{
    int written = 0;
    int nbytes = 0;

    while (written < (int)bufsize)
    {

        nbytes =
            send(conn_ctx->connfd, (char*)buf + written, bufsize - written, 0);

        if (nbytes == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            perror("write");
            return -1;
        }
        if (nbytes == 0)
        {
            break;
        }

        written += nbytes;
    }

    return written;
}

int get_regex_matches(const char* str, char* regex, char** matches)
{
    int nmatches = 0;
    regex_t re; // todo to check if initialized
    char err_msg[MAX_STRING_SIZE];

    int err = 0;
    err = regcomp(&re, regex, REG_EXTENDED | REG_NEWLINE);
    if (err != 0)
    {
        regerror(err, &re, err_msg, MAX_STRING_SIZE);
        print_debug(ERROR, "regcomp error: %s\n", err_msg);
        return -1;
    }

    int ngroups = (int)re.re_nsub + 1; // + 1 for whole match
    regmatch_t rm[ngroups];

    err = regexec(&re, str, ngroups, rm, 0);
    if (err == 0)
    {
        for (int i = 1; i < ngroups; i++)
        {
            if (rm[i].rm_so == -1)
            {
                break; // no more matches
            }

            int len = rm[i].rm_eo - rm[i].rm_so;
            matches[nmatches] = (char*)malloc(sizeof(char) * len + 1);
            if (matches[nmatches] == NULL)
            {
                perror("malloc mathes[i]: get_regex_matches");
                return -1;
            }
            strncpy(matches[nmatches], str + rm[i].rm_so, len);
            matches[nmatches][len] = '\0';
            nmatches++;
        }
        regfree(&re);
    }
    else
    {
        regerror(err, &re, err_msg, MAX_STRING_SIZE);
        print_debug(ERROR, "regexec error << %s >>: %s\n", regex, err_msg);
        regfree(&re);
        return -1;
    }

    return nmatches;
}

char* extract_request_token(char* raw, http_request_token_t http_req_token)
{
    char* start = NULL;
    char* end = NULL;

    switch (http_req_token)
    {
        case HTTP_REQ_TOKEN_REQUEST_LINE:
            start = raw;
            end = strstr(raw, CRLF);
            if (end == NULL)
            {
                print_debug(ERROR,
                            "extract http request line end not found in %s\n",
                            raw);
                return NULL;
            }
            break;

        case HTTP_REQ_TOKEN_HEADERS:
            start = strstr(raw, CRLF);
            if (start == NULL)
            {
                print_debug(
                    ERROR,
                    "exctract http request headers start not found in %s\n",
                    raw);
                return NULL;
            }
            start = start + strlen(CRLF);
            end = strstr(start, CRLFCRLF);
            if (end == NULL)
            {
                print_debug(ERROR,
                            "exctract http headers end not found in %s\n", raw);
                return NULL;
            }
            break;
        case HTTP_REQ_TOKEN_BODY:
            print_debug(WARN, "extracting http request body not implemented\n");
            return NULL;
        default:
            print_debug(INFO, "unknown http request token\n");
            return NULL;
    }

    int rtoken_length = end - start;
    char* rtoken = (char*)malloc(rtoken_length + 1);
    if (rtoken == NULL)
    {
        perror("malloc rtoken: extract_request_token");
        return NULL;
    }
    memset(rtoken, 0, rtoken_length + 1);
    strncpy(rtoken, start, rtoken_length);
    // rtoken[rtoken_length] = '\0';
    return rtoken;
}

void free_match_regex(char** matches, int nmatches)
{

    if (matches)
    {

        for (int i = 0; i < nmatches; i++)
        {
            if (matches[i])
            {
                free(matches[i]);
            }
        }

        free(matches);
    }
}

int parse_http_request_line(http_request_t* req, char* req_line,
                            char* default_file,
                            log_entry_config_t* msg_log_entry)
{
    int rstatus = -1;
    int ntokens = 3; // method, uri, http_version
    char** rlmatches = NULL;
    int nmatches = 0;
    rlmatches = (char**)calloc((ntokens + 1),
                               sizeof(char*)); // + 8 byte for a whole match
    if (rlmatches == NULL)
    {
        print_debug(ERROR, "malloc rlmatches: parse_http_request_line %s\n",
                    strerror(errno));
        return -1;
    }

    nmatches = get_regex_matches(req_line, REGEX_REQUEST_LINE, rlmatches);

    if (nmatches != ntokens)
    {

        goto exit;
    }

    char method_buf[MAX_STRING_SIZE] = {'\0'};
    memcpy(method_buf, rlmatches[0], MAX_STRING_SIZE - 1);

    char uri_buf[MAX_STRING_SIZE] = {'\0'};
    memcpy(uri_buf, rlmatches[1], MAX_STRING_SIZE - 1);

    char http_version_buf[MAX_STRING_SIZE] = {'\0'};
    memcpy(http_version_buf, rlmatches[2], MAX_STRING_SIZE - 1);

    if (strncmp(method_buf, S_GET, strlen(method_buf)) == 0)
    {
        req->m = GET;
    }
    else
    {

        req->client_err |= ERR_CLT_UNSUPPORTED_MTHD;
        req->m = UNSUPPORTED;
    }

    msg_log_entry->cs_method = req->m;

    if (parse_uri(uri_buf, req, default_file, msg_log_entry) < 0)
    {
        goto exit;
    }

    char* slash = strstr(http_version_buf, "/");
    if (slash == NULL)
    {

        req->client_err |= ERR_CLT_UNSUPPORTED_HTTP_VERSION;
        req->http_version = 1.1f;
    }
    else
    {
        req->http_version = (float)atof(slash + 1);
    }

    rstatus = 0;
exit:
    free_match_regex(rlmatches, ntokens + 1); // 1 for a whole match

    return rstatus;
}

int parse_http_headers(http_request_t* req, char* extr_headers)
{
    req->nhttp_headers = 0;
    regex_t re_hdr;
    int err = 0;
    char err_msg[MAX_STRING_SIZE];
    char* cursor = extr_headers;
    int key_offset_start;
    int key_offset_end;
    int val_offset_start;
    int val_offset_end;
    int key_inx = 1;
    int val_inx = 3;
    int count_headers = 0;
    int new_line_inx = 4;
    int new_line_eo;

    err = regcomp(&re_hdr, REGEX_REQUEST_HDR, REG_EXTENDED | REG_NEWLINE);
    int nmatches = re_hdr.re_nsub + 1;

    if (err != 0)
    {
        regerror(err, &re_hdr, err_msg, MAX_STRING_SIZE);
        print_debug(ERROR, "err regcomp %s\n", err_msg);
        goto exit_regerror;
    }

    cursor = extr_headers;
    while (1)
    {
        regmatch_t rm_hdr[nmatches];

        err = regexec(&re_hdr, cursor, nmatches, rm_hdr, 0);
        if (err != 0)
        {
            // no more matches

            break;
        }

        val_offset_end = rm_hdr[val_inx].rm_eo;
        cursor = cursor + val_offset_end + 1;
        count_headers = count_headers + 1;
    }

    cursor = extr_headers;
    req->http_headers =
        (http_header_t**)malloc(count_headers * sizeof(http_header_t*));
    if (req->http_headers == NULL)
    {
        print_debug(ERROR,
                    "err malloc req->http_headers: parse_http_headers\n");
        goto exit_req_http_headers;
    }

    req->nhttp_headers = count_headers;

    for (int i = 0; i < count_headers; i++)
    {
        regmatch_t rm_hdr[nmatches];
        err = regexec(&re_hdr, cursor, nmatches, rm_hdr, 0);
        if (err != 0)
        {
            // no more matches
            break;
        }

        key_offset_start = rm_hdr[key_inx].rm_so;
        key_offset_end = rm_hdr[key_inx].rm_eo;
        char* key = cursor + key_offset_start;
        cursor[key_offset_end] = '\0';

        val_offset_start = rm_hdr[val_inx].rm_so;
        val_offset_end = rm_hdr[val_inx].rm_eo;
        char* val = cursor + val_offset_start;
        cursor[val_offset_end] = '\0';

        new_line_eo = rm_hdr[new_line_inx].rm_eo;

        http_header_t* http_hdr = http_header_constructor(key, val);
        if (http_hdr == NULL)
        {
            print_debug(ERROR, "http_header_constructor: parse_http_headers\n");
            goto exit_http_hdr;
        }

        req->http_headers[i] = http_hdr;
        cursor = cursor + new_line_eo;
    }

    regfree(&re_hdr);
    return 0;

exit_regerror:
    return -1;

exit_req_http_headers:
    regfree(&re_hdr);
    goto exit_regerror;

exit_http_hdr:
    for (int i = 0; i < req->nhttp_headers; i++)
    {
        http_header_destructor(req->http_headers[i]);
    }
    free(req->http_headers);
    goto exit_req_http_headers;
}

int parse_http_request(http_request_t* req, char* extr_line, char* extr_headers,
                       char* extr_body, char* default_file,
                       log_entry_config_t* msg_log_entry)
{
    if (parse_http_request_line(req, extr_line, default_file, msg_log_entry) !=
        0)
    {
        print_debug(ERROR, "error parsing request line\n");
        return -1;
    }

    if (parse_http_headers(req, extr_headers) != 0)
    {
        print_debug(ERROR, "error parsing request headers \n");
        return -1;
    }

    return 0;
}

http_request_t* http_request_constructor(char* raw, char* default_file,
                                         log_entry_config_t* msg_log_entry)
{
    http_request_t* http_req =
        (http_request_t*)calloc(sizeof(http_request_t), 1);
    if (http_req == NULL)
    {

        goto exit_http_req;
    }

    char* extract_request_line =
        extract_request_token(raw, HTTP_REQ_TOKEN_REQUEST_LINE);
    if (extract_request_line == NULL)
    {
        goto exit;
    }

    char* extract_request_headers =
        extract_request_token(raw, HTTP_REQ_TOKEN_HEADERS);
    if (extract_request_headers == NULL)
    {
        free(extract_request_line);
        goto exit;
    }

    char* extract_request_body =
        extract_request_token(raw, HTTP_REQ_TOKEN_BODY);
    if (extract_request_body == NULL)
    {
        print_debug(INFO, "no body in request\n");
    }

    if (parse_http_request(http_req, extract_request_line,
                           extract_request_headers, extract_request_body,
                           default_file, msg_log_entry) != 0)
    {
        free(extract_request_line);
        free(extract_request_headers);
        goto exit;
    }

    free(extract_request_line);
    free(extract_request_headers);

    return http_req;

exit_http_req:
    return NULL;

exit:
    http_request_destructor(http_req);
    goto exit_http_req;
}

void http_request_destructor(http_request_t* http_req)
{
    if (http_req->uri != NULL)
    {
        free(http_req->uri);
    }

    if (http_req->http_headers != NULL)
    {
        for (int i = 0; i < http_req->nhttp_headers; ++i)
        {
            http_header_destructor(http_req->http_headers[i]);
        }

        free(http_req->http_headers);
    }

    free(http_req);
}

int parse_uri(char* uri, http_request_t* req, char* default_file,
              log_entry_config_t* msg_log_entry)
{
    char resolved_uri_buf[MAX_STRING_SIZE] = {'\0'};
    char temp_uri_buf[MAX_STRING_SIZE] = {'\0'};

    if (strncmp(uri, SLASH, strlen(uri)) == 0)
    {

        strncat(temp_uri_buf, default_file, strlen(default_file) + 1);
    }

    if (realpath(temp_uri_buf, resolved_uri_buf) == NULL)
    {

        req->client_err |= ERR_CLT_URI_NOT_FOUND;
        req->uri = NULL;
        goto exit;
    }

    req->uri = (char*)malloc(strlen(resolved_uri_buf) + 1);
    if (req->uri == NULL)
    {
        print_debug(ERROR, "malloc req->uri: parse_uri\n");
        return -1;
    }

    strncpy(req->uri, resolved_uri_buf, strlen(resolved_uri_buf));
    req->uri[strlen(resolved_uri_buf)] = '\0';
exit:

    strncpy(msg_log_entry->cs_uri, uri, strlen(uri));
    msg_log_entry->cs_uri[strlen(uri)] = '\0';

    return 0;
}

int handle_clt(conn_ctx_t* conn_ctx, char* default_file, char* s_ip, char* c_ip,
               FILE* msg_log_fp, uint8_t* http_srv_options)
{
    log_entry_config_t msg_log_entry;
    msg_log_entry.c_ip = c_ip;
    msg_log_entry.s_ip = s_ip;

    int success = 0;

    char* raw = NULL;

    if (g_is_https)
    {
        raw = mtls_read_msg(conn_ctx);
    }
    else
    {
        raw = read_mes(conn_ctx);
    }

    if (raw == NULL)
    {
        goto exit_raw;
    }

    http_request_t* http_req =
        http_request_constructor(raw, default_file, &msg_log_entry);
    if (http_req == NULL)
    {
        print_debug(ERROR, "http request not constructed\n");
        goto exit_http_req;
    }

    http_response_t* http_res =
        http_response_constructor(http_req, &msg_log_entry, http_srv_options);
    if (http_res == NULL)
    {
        print_debug(ERROR, "http response not constructed\n");
        goto exit_http_res;
    }

    write_fn_t send_body_fn = NULL;

    send_body_fn = conn_ctx->write_fn;

    if (*(http_srv_options)&HTTP_SRV_OPT_TE_CHUNKED)
    {
        send_body_fn = &write_chunked_mes;
    }

    if (http_res->send(conn_ctx, http_res, send_body_fn) != 0)
    {

        goto exit_http_res_send;
    }

    char log_entry_buf[MAX_STRING_SIZE];
    memset(log_entry_buf, 0, MAX_STRING_SIZE);
    if (serialize_msg_log_entry(log_entry_buf, MAX_STRING_SIZE,
                                &msg_log_entry) < 0)
    {
        goto exit_http_res_send;
    }

    msg_log(msg_log_fp, log_entry_buf, 0);
    fflush(msg_log_fp);
    fclose(msg_log_fp);

    success = 1;
    goto exit_http_res_send;

exit_raw:

    if (success == 1)
    {
        return 0;
    }
    else
    {
        return -1;
    }

exit_http_req:
    free(raw);
    goto exit_raw;

exit_http_res:
    http_request_destructor(http_req);
    goto exit_http_req;

exit_http_res_send:
    http_response_destructor(http_res);
    goto exit_http_req;
}

int construct_http_response_status_line(http_request_t* http_req,
                                        http_response_t* http_res,
                                        log_entry_config_t* msg_log_entry)
{
    uint16_t status_code = 200;
    char* reason_phrase = REASON_PHRASE_200;

    if (http_req->client_err > 0)
    {
        if (http_req->client_err & ERR_CLT_UNSUPPORTED_MTHD)
        {
            status_code = N_500;
            reason_phrase = REASON_PHRASE_500;
        }
        else if (http_req->client_err & ERR_CLT_UNSUPPORTED_HTTP_VERSION)
        {
            status_code = N_505;
            reason_phrase = REASON_PHRASE_505;
        }
        else if (http_req->client_err & ERR_CLT_CORRUPTED_HEADERS)
        {
            status_code = N_400;
            reason_phrase = REASON_PHRASE_400;
        }
        else if (http_req->client_err & ERR_CLT_URI_NOT_FOUND)
        {
            status_code = N_404;
            reason_phrase = REASON_PHRASE_404;
        }
    }

    http_res->status_code = status_code;

    http_res->reason_phrase = (char*)malloc(strlen(reason_phrase) + 1);
    if (http_res->reason_phrase == NULL)
    {
        print_debug(ERROR, "malloc construct_http_response_status err %s\n",
                    strerror(errno));
        return -1;
    }
    strncpy(http_res->reason_phrase, reason_phrase, strlen(reason_phrase));
    http_res->reason_phrase[strlen(reason_phrase)] = '\0';

    http_res->http_version = http_req->http_version;

    msg_log_entry->sc_status = http_res->status_code;

    return 0;
}

char* serialize_http_response_status_line(http_response_t* http_res)
{
    char status_line[MAX_STRING_SIZE];
    sprintf(status_line, "HTTP/%.1f %d %s%s", http_res->http_version,
            http_res->status_code, http_res->reason_phrase, CRLF);
    int status_line_len = strlen(status_line);
    char* new_status_line = (char*)malloc(status_line_len + 1);
    if (new_status_line == NULL)
    {
        print_debug(ERROR,
                    "malloc new_status_line: "
                    "construct_http_response_status_line %s\n",
                    strerror(errno));
        return NULL;
    }

    strncpy(new_status_line, status_line, status_line_len);
    new_status_line[status_line_len] = '\0';

    return new_status_line;
}

int construct_http_response_headers(http_request_t* http_req,
                                    http_response_t* http_res,
                                    uint8_t* http_srv_options)
{

    http_header_t http_response_headers_buf[NUMBER_OF_HTTP_RES_HDR_KEYS];
    int count_headers = 0;
    http_res->nhttp_headers = 0;

    for (int i = 0; i < NUMBER_OF_HTTP_RES_HDR_KEYS; ++i)
    {
        switch ((enum HttpResponseHeaderKey)i)
        {
            case HTTP_RES_HDR_KEY_SERVER:

                http_response_headers_buf[count_headers] =
                    http_response_headers_data[HTTP_RES_HDR_KEY_SERVER];
                break;
            case HTTP_RES_HDR_KEY_CONTENT_TYPE:

                http_response_headers_buf[count_headers] =
                    http_response_headers_data[HTTP_RES_HDR_KEY_CONTENT_TYPE];

                if (http_res->uri == NULL)
                {
                    break;
                }

                char* last_4_chars_of_file_name =
                    http_res->uri + (strlen(http_res->uri) - 4);

                if (strncasecmp(last_4_chars_of_file_name, "html", 4))
                {

                    http_header_t new_cont_type_hdr = http_response_headers_data
                        [HTTP_RES_HDR_KEY_CONTENT_TYPE];
                    new_cont_type_hdr.value = "multipart/formdata";
                    http_response_headers_buf[count_headers] =
                        new_cont_type_hdr;
                }

                break;
            case HTTP_RES_HDR_KEY_CONNECTION:

                if (!is_http_res_hdr_supported(HTTP_RES_HDR_KEY_CONNECTION,
                                               HTTP_REQ_HDR_KEY_CONNECTION,
                                               http_req))
                {
                    print_debug(INFO, "connection alive is not supported\n");
                    continue;
                }

                http_response_headers_buf[count_headers] =
                    http_response_headers_data[HTTP_RES_HDR_KEY_CONNECTION];
                *(http_srv_options) |= HTTP_SRV_OPT_KEEP_ALIVE;

                http_response_headers_buf[++count_headers] =
                    http_response_headers_data[HTTP_RES_HDR_KEEP_ALIVE];
                break;
            case HTTP_RES_HDR_KEY_TRANSFER_ENCODING:

                if (!is_http_res_hdr_supported(
                        HTTP_RES_HDR_KEY_TRANSFER_ENCODING,
                        HTTP_REQ_HDR_KEY_TRANSFER_ENCODING, http_req))
                {
                    continue;
                }

                http_response_headers_buf[count_headers] =
                    http_response_headers_data
                        [HTTP_RES_HDR_KEY_TRANSFER_ENCODING];
                *(http_srv_options) |= HTTP_SRV_OPT_TE_CHUNKED;

                break;
            default:

                count_headers -= 1;
                break;
        }
        count_headers++;
    }

    http_res->nhttp_headers = count_headers;
    http_res->http_headers =
        (http_header_t*)malloc(sizeof(http_header_t) * count_headers);
    if (http_res->http_headers == NULL)
    {
        print_debug(ERROR, "malloc http_headers: construct_http_headers\n");
        return -1;
    }

    for (int i = 0; i < count_headers; ++i)
    {
        http_res->http_headers[i].key = http_response_headers_buf[i].key;
        http_res->http_headers[i].value = http_response_headers_buf[i].value;
    }

    return 0;
}

char* serialize_http_response_headers(http_response_t* http_res)
{
    char headers[MAX_STRING_SIZE];
    int count_headers;
    char* cursor = headers;
    char* key;
    char* val;
    int end;

    for (count_headers = 0; count_headers < http_res->nhttp_headers;
         ++count_headers)
    {
        key = http_res->http_headers[count_headers].key;
        val = http_res->http_headers[count_headers].value;
        sprintf(cursor, "%s: %s%s", key, val, CRLF);
        end = strlen(cursor);
        cursor = cursor + end;
    }

    // to separate headers from the body
    sprintf(cursor, "%s", CRLF);

    char* new_headers = (char*)malloc(strlen(headers) + 1);
    if (new_headers == NULL)
    {
        print_debug(ERROR,
                    "malloc new_headers: construct_http_response_headers %s\n",
                    strerror(errno));
        return NULL;
    }
    strncpy(new_headers, headers, strlen(headers));
    new_headers[strlen(headers)] = '\0';

    return new_headers;
}

int send_http_response_fn(conn_ctx_t* conn_ctx, http_response_t* http_res,
                          write_fn_t send_body_fn)
{

    write_wrap_t ww_sl_hdr;
    write_wrap_t ww_body;

    if (g_is_https)
    {
        ww_sl_hdr.write_fn = &mtls_write_msg;
    }
    else
    {
        ww_sl_hdr.write_fn = &write_mes;
    }

    ww_body.write_fn = send_body_fn;

    int success = 0;

    char* status_line = serialize_http_response_status_line(http_res);
    if (status_line == NULL)
    {
        goto exit_status_line;
    }

    char* http_res_headers = serialize_http_response_headers(http_res);
    if (http_res_headers == NULL)
    {
        goto exit_http_res_headers;
    }

    int written = 0;
    int bytes = 0;
    while (written < (int)strlen(status_line))
    {
        bytes =
            ww_sl_hdr.write_fn(conn_ctx, status_line, strlen(status_line), 0);
        if (bytes == -1)
        {
            goto exit_bytes;
        }
        written += bytes;
    }

    written = 0;
    bytes = 0;

    while (written < (int)strlen(http_res_headers))
    {
        bytes = ww_sl_hdr.write_fn(conn_ctx, http_res_headers,
                                   strlen(http_res_headers), 0);
        if (bytes == -1)
        {
            goto exit_bytes;
        }
        written += bytes;
    }

    FILE* file = NULL;
    void* file_buf = NULL;
    size_t file_buf_size = MAX_STRING_SIZE;
    size_t bytes_read = 0;
    uint8_t is_last_chunk = 0;

    if (http_res->uri != NULL)
    {

        file = fopen(http_res->uri, "rb");

        if (file == NULL)
        {
            print_debug(ERROR, "err fopen: send_http_response_fn\n");
            goto exit_file;
        }

        file_buf = (char*)malloc(file_buf_size * sizeof(char));
        if (file_buf == NULL)
        {
            print_debug(ERROR, "err malloc buffer: send_http_response_fn\n");
            goto exit_bytes;
        }

        while (!feof(file) && !ferror(file))
        {
            memset(file_buf, 0, file_buf_size);

            bytes_read = fread(file_buf, 1, file_buf_size, file);

            is_last_chunk = bytes_read < file_buf_size;

            ww_body.write_fn(conn_ctx, file_buf, bytes_read, is_last_chunk);
        }

        if (ferror(file))
        {
            print_debug(ERROR, "error reading from a file\n");
            goto exit_error_file;
        }
    }

    success = 1;
    goto exit_error_file;

exit_status_line:
    if (success == 1)
    {
        return 0;
    }
    else
    {

        return -1;
    }

exit_http_res_headers:
    if (status_line)
    {
        free(status_line);
    }
    goto exit_status_line;

exit_bytes:
    if (http_res_headers)
    {
        free(http_res_headers);
    }
    goto exit_http_res_headers;

exit_file:
    goto exit_bytes;

exit_error_file:
    if (file_buf != NULL)
    {
        free(file_buf);
    }
    if (file != NULL)
    {
        fclose(file);
    }
    goto exit_file;
}

http_response_t* http_response_constructor(http_request_t* http_req,
                                           log_entry_config_t* msg_log_entry,
                                           uint8_t* http_srv_options)
{
    http_response_t* http_res =
        (http_response_t*)malloc(sizeof(http_response_t));
    if (http_res == NULL)
    {
        print_debug(ERROR, "malloc http_res: http_response_constructor");
        goto exit_http_res;
    };

    http_res->uri =
        (http_req->client_err & ERR_CLT_URI_NOT_FOUND) ? NULL : http_req->uri;
    http_res->send = &send_http_response_fn;

    if (construct_http_response_status_line(http_req, http_res, msg_log_entry) <
        0)
    {
        goto exit;
    }

    if (construct_http_response_headers(http_req, http_res, http_srv_options) <
        0)
    {
        goto exit;
    }

    return http_res;

exit_http_res:
    return NULL;

exit:
    http_response_destructor(http_res);
    goto exit_http_res;
}

http_header_t* http_header_constructor(char* key, char* value)
{
    http_header_t* new_header = (http_header_t*)malloc(sizeof(http_header_t));
    if (new_header == NULL)
    {
        print_debug(ERROR, "new_header: http_header_constructor\n");
        goto exit_new_header;
    }

    new_header->key = (char*)malloc(strlen(key) + 1);
    if (new_header->key == NULL)
    {
        print_debug(ERROR, "malloc key: http_header_constructor\n");
        goto exit;
    }
    strncpy(new_header->key, key, strlen(key));
    new_header->key[strlen(key)] = '\0';

    new_header->value = (char*)malloc(strlen(value) + 1);
    if (new_header->value == NULL)
    {
        print_debug(ERROR, "malloc value: http_header_constructor\n");
        goto exit;
    }
    strncpy(new_header->value, value, strlen(value));
    new_header->value[strlen(value)] = '\0';

    return new_header;

exit_new_header:
    return NULL;

exit:
    http_header_destructor(new_header);
    goto exit_new_header;
}

void http_header_destructor(http_header_t* http_hdr)
{
    if (http_hdr->key != NULL)
    {
        free(http_hdr->key);
    }

    if (http_hdr->value != NULL)
    {
        free(http_hdr->value);
    }

    free(http_hdr);
}

void http_response_destructor(http_response_t* http_res)
{
    if (http_res->uri != NULL)
    {
        free(http_res->uri);
    }

    if (http_res->reason_phrase != NULL)
    {
        free(http_res->reason_phrase);
    }

    if (http_res->http_headers != NULL)
    {
        free(http_res->http_headers);
    }

    free(http_res);
}

void chunk_constructor(char* msg, size_t msgsize, char* chunk_buf,
                       size_t chunk_bufsize)
{

    memset(chunk_buf, 0, chunk_bufsize);
    if (msg == NULL && msgsize == 0)
    {
        // final chunk;
        sprintf(chunk_buf, "0%s%s", CRLF, CRLF);
    }
    else
    {
        sprintf(chunk_buf, "%X%s%s%s", (unsigned int)msgsize, CRLF, msg, CRLF);
    }
}

http_header_t*
get_http_response_header_data(enum HttpResponseHeaderKey http_res_hdr_key,
                              http_header_t* http_response_headers_data)
{
    if ((int)http_res_hdr_key < 0 ||
        http_res_hdr_key >= (int)NUMBER_OF_HTTP_RES_HDR_KEYS)
    {
        return NULL;
    }

    return &(http_response_headers_data[http_res_hdr_key]);
}

http_header_t*
get_http_request_header(enum HttpRequestHeaderKey http_req_hdr_key,
                        http_request_t* http_req)
{
    if ((int)http_req_hdr_key < 0 ||
        http_req_hdr_key >= NUMBER_OF_HTTP_REQ_HDR_KEYS)
    {
        return NULL;
    }

    char* shdr_key = http_request_headers_keys[http_req_hdr_key];

    for (int i = 0; i < http_req->nhttp_headers; ++i)
    {
        if (strncmp(shdr_key, http_req->http_headers[i]->key,
                    strlen(shdr_key)) == 0)
        {
            return http_req->http_headers[i];
        }
    }

    return NULL;
}

http_header_t*
get_http_response_header(enum HttpResponseHeaderKey http_res_hdr_key,
                         http_response_t* http_res)
{
    if (http_res_hdr_key < 0 || http_res_hdr_key >= NUMBER_OF_HTTP_RES_HDR_KEYS)
    {
        return NULL;
    }

    char* shttp_res_hdr_key = http_response_headers_data[http_res_hdr_key].key;

    for (int i = 0; i < http_res->nhttp_headers; ++i)
    {
        if (strncmp(shttp_res_hdr_key,
                    http_res->http_headers[(enum HttpResponseHeaderKey)i].key,
                    strlen(shttp_res_hdr_key)) == 0)
        {
            return &http_res->http_headers[(enum HttpResponseHeaderKey)i];
        }
    }

    return NULL;
}

int write_chunked_mes(conn_ctx_t* conn_ctx, void* mes_buf, size_t mes_buf_size,
                      uint8_t is_last_chunk)
{
    size_t chunk_buf_size = MAX_STRING_SIZE;
    char chunk_buf[chunk_buf_size];
    memset(chunk_buf, 0, chunk_buf_size);
    chunk_constructor(mes_buf, mes_buf_size, chunk_buf, chunk_buf_size);
    conn_ctx->write_fn(conn_ctx, chunk_buf, strlen(chunk_buf), 0);

    if (is_last_chunk > 0)
    {
        chunk_constructor(NULL, 0, chunk_buf, chunk_buf_size);
        conn_ctx->write_fn(conn_ctx, chunk_buf, strlen(chunk_buf), 0);
    }

    return 0;
}

uint8_t is_http_res_hdr_supported(enum HttpResponseHeaderKey http_res_hdr_key,
                                  enum HttpRequestHeaderKey http_req_hdr_key,
                                  http_request_t* http_req)
{

    if (http_req_hdr_key < 0 || http_req_hdr_key >= NUMBER_OF_HTTP_REQ_HDR_KEYS)
    {
        print_debug(ERROR, "invalid http request header key provided\n");
        return 0;
    }

    uint8_t is_supported = 0;

    http_header_t* http_req_hdr =
        get_http_request_header(http_req_hdr_key, http_req);
    if (http_req_hdr == NULL)
    {
        print_debug(WARN, "no header [%s] in http request\n",
                    http_request_headers_keys[http_req_hdr_key]);
        return 0;
    }
    char* http_req_hdr_val = http_req_hdr->value;

    http_header_t* http_res_hdr_data = get_http_response_header_data(
        http_res_hdr_key, http_response_headers_data);

    char* http_res_hdr_data_val = http_res_hdr_data_val =
        http_res_hdr_data->value;

    char src_lower[strlen(http_res_hdr_data_val) + 1];
    to_lower(http_res_hdr_data_val, src_lower);
    char dst_lower[strlen(http_req_hdr_val) + 1];
    to_lower(http_req_hdr_val, dst_lower);

    if (strncmp(src_lower, dst_lower, strlen(src_lower)) == 0)
    {
        is_supported = 1;
    }

    return is_supported;
}

void to_lower(char* src, char* dst)
{
    char ch = 0;
    int inx = 0;
    while ((ch = src[inx]))
    {
        dst[inx] = tolower((int)ch);
        inx++;
    }
    dst[inx] = '\0';
}
