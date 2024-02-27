#ifndef CONFIG_API_H
#define CONFIG_API_H

#include <linux/limits.h>
#include <stdint.h>

#define REGEX_COMMENT "^\\w*#"
#define INET6_ADDRSTRLEN 1024
#define REGEX_INET4_ADDRESS "[0-9]+.[0-9]+.[0-9]+.[0-9]+"
#define MAX_ERR_MSG 1024
#define ROOT_S "ROOT"
#define ROOT_FOLDER_DEFAULT "/home/taras/taras-ivashchuk-fork/http_server/www/"
#define HTTP_PORT_S "HTTP_PORT"
#define HTTP_PORT_DEFAULT 80
#define HTTPS_PORT_S "HTTPS_PORT"
#define HTTPS_PORT_DEFAULT 443
#define ADDRESS_S "ADDRESS"
#define ADDRESS_DEFAULT "127.0.0.1"
#define DEFAULT_FILE_S "DEFAULT_FILE"
#define DEFAULT_FILE_DEFAULT "index.html"
#define CHUNK_ENCODING_S "CHUNK_ENCODING"
#define CHUNK_ENCODING_DEFAULT 1
#define W3C_FILE_S "W3C_FILE"
#define W3C_FILE_DEFAULT "stdout"
#define SSL_KEY_S "SSL_KEY"
#define SSL_KEY_DEFAULT "ssl_cert_key/my_private_key"
#define SSL_CRT_S "SSL_CRT"
#define SSL_CRT_DEFAULT "ssl_cert_key/my_cert_req"
#define DEBUG_LVL_S "DEBUG_LVL"

typedef enum
{
    ROOT,
    HTTP_PORT,
    ADDRESS,
    DEFAULT_FILE,
    CHUNK_ENCODING,
    W3C_FILE,
    HTTPS_PORT,
    SSL_KEY,
    SSL_CRT,
    DEBUG_LVL,
    COUNT_TOKENS,
} conf_type_t;

typedef struct ConfToken
{
    char* name;
    conf_type_t type;
    int (*validator)(char* svalue);
    union
    {
        char sval[PATH_MAX];
        uint16_t nu16val;
    };
} conf_token_t;

conf_token_t* get_config_token(char* str);
int set_config_data(conf_token_t* ct, char* value);
void* config_get_data(conf_type_t conf_type);
int parse_config(char* config);

#endif
