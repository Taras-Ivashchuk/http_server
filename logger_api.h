#ifndef LOGGER_API_H
#define LOGGER_API_H
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>

#define TS_BUF_LENGTH 30
#define HDR_BUF_LENGTH 1024
#define HDR_VERSION_LENGTH 25
#define HDR_FIELDS_LENGTH 100
#define HDR_OPTION_LENGTH 100
#define CRLF "\r\n"
#define SPACE " "
#define HYPHEN "-"
#define DATE_OPTION 0x01
#define SOFTWARE_OPTION 0x02
#define ESC_COLOR_RED "\033[1;31m"
#define ESC_COLOR_YELLOW "\033[1;33m"
#define ESC_COLOR_GREEN "\033[1;32m"
#define ESC_COLOR_RESET "\033[1;0m"

typedef enum
{
    GET,
    UNSUPPORTED,
    METHODS_COUNT
} Method;

typedef enum
{
    DATE = 0,
    TIME,
    C_IP,
    CS_METHOD,
    CS_URI,
    S_IP,
    SC_STATUS,
    FIELDS_COUNT
} field_t;

typedef struct
{
    struct tm date;
    struct tm time;
    char* c_ip;
    char cs_uri[PATH_MAX];
    char* s_ip;
    Method cs_method;
    uint16_t sc_status;
} log_entry_config_t;

typedef enum
{
    NONE,
    ERROR,
    WARN,
    INFO,
    COUNT_LOG_LVL
} log_lvl_t;

void msg_log(FILE* fp, char* msg, uint8_t options);
char* get_method_name(Method m, char** methods);
char* get_msg_log_field_name(field_t field_type, char** fields);
void construct_msg_log_header(char* header_buf, size_t header_size,
                              float version, char** fields, uint8_t options);
int serialize_msg_log_entry(char* entry_buf, size_t entry_size,
                            log_entry_config_t* msg_log_entry);
void print_debug(log_lvl_t log_lvl, char* fmt, ...);

#endif
