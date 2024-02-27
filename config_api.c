#include "config_api.h"
#include "logger_api.h"
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int is_comment(char* line);
char** split_strings(char* str, char* separators, int* count_strings);
void free_split_strings(char** split_strings, int strings_count);
int is_valid_root(char* value);
int is_valid_port(char* port);
int is_valid_address(char* address);
int is_valid_default_file(char* filename);
int is_valid_w3c_file(char* filename);

static conf_token_t conf_data[COUNT_TOKENS] = {
    [ROOT] = {.validator = is_valid_root,
              .name = ROOT_S,
              .sval = ROOT_FOLDER_DEFAULT,
              .type = ROOT},
    [HTTP_PORT] = {.validator = is_valid_port,
                   .name = HTTP_PORT_S,
                   .nu16val = HTTP_PORT_DEFAULT,
                   .type = HTTP_PORT},
    [HTTPS_PORT] = {.validator = is_valid_port,
                    .name = HTTPS_PORT_S,
                    .nu16val = HTTPS_PORT_DEFAULT,
                    .type = HTTPS_PORT},
    [ADDRESS] = {.name = ADDRESS_S,
                 .sval = ADDRESS_DEFAULT,
                 .type = ADDRESS,
                 .validator = is_valid_address},
    [DEFAULT_FILE] = {.validator = is_valid_default_file,
                      .name = DEFAULT_FILE_S,
                      .sval = DEFAULT_FILE_DEFAULT,
                      .type = DEFAULT_FILE},
    [CHUNK_ENCODING] = {.validator = NULL,
                        .name = CHUNK_ENCODING_S,
                        .nu16val = CHUNK_ENCODING_DEFAULT,
                        .type = CHUNK_ENCODING},
    [W3C_FILE] = {.validator = is_valid_w3c_file,
                  .name = W3C_FILE_S,
                  .sval = W3C_FILE_DEFAULT,
                  .type = W3C_FILE},
    [SSL_KEY] = {.validator = NULL,
                 .name = SSL_KEY_S,
                 .sval = SSL_KEY_DEFAULT,
                 .type = SSL_KEY},
    [SSL_CRT] = {.validator = NULL,
                 .name = SSL_CRT_S,
                 .sval = SSL_CRT_DEFAULT,
                 .type = SSL_CRT},
    [DEBUG_LVL] = {.validator = NULL,
                   .name = DEBUG_LVL_S,
                   .nu16val = 0,
                   .type = DEBUG_LVL}};

int is_valid_root(char* root)
{
    if (root == NULL)
    {
        print_debug(ERROR, "value is missing in config file\n");
        return -1;
    }
    char resolved[PATH_MAX];
    if (realpath(root, resolved) == NULL)
    {
        print_debug(ERROR, "realpath err: no found path: %s\n", root);
        strerror(errno);
        return -1;
    }
    return 0;
}

int is_valid_port(char* port)
{
    if (port == NULL)
    {
        print_debug(ERROR, "value is missing in config file\n");
        return -1;
    }
    int iport = (int)atoi(port);
    if (iport < 1 || iport > 65535)
    {
        print_debug(ERROR, "wrong port \n");
        return -1;
    }

    return 0;
}

int is_valid_default_file(char* filename)
{
    if (filename == NULL)
    {
        print_debug(ERROR, "value is missing in config file\n");
        return -1;
    }
    char buffer[PATH_MAX];
    char* root = (char*)config_get_data(ROOT);
    strncpy(buffer, root, strlen(root));
    buffer[strlen(root)] = '\0';
    strncat(buffer, filename, strlen(filename) + 1);

    return !(is_valid_root(buffer) == 0);
}

int is_valid_w3c_file(char* filename)
{
    if (filename == NULL)
    {
        print_debug(ERROR, "value is missing in config file\n");
        return -1;
    }

    return !(is_valid_root(filename) == 0);
}

int is_valid_address(char* address)
{
    if (address == NULL)
    {
        print_debug(ERROR, "value is missing in config file\n");
        return -1;
    }
    regex_t re;
    char err_msg[MAX_ERR_MSG];
    int err;

    err = regcomp(&re, REGEX_INET4_ADDRESS, REG_EXTENDED | REG_NEWLINE);
    if (err > 0)
    {
        regerror(err, &re, err_msg, MAX_ERR_MSG);
        print_debug(ERROR, "regcomp error\n");
        return -1;
    }

    regmatch_t rm;
    size_t nmatch = 1;

    err = regexec(&re, address, nmatch, &rm, 0);
    if (err > 0)
    {
        regerror(err, &re, err_msg, MAX_ERR_MSG);
        print_debug(ERROR, "is_valid_address regexec %s\n", err_msg);
        return -1;
    }

    return 0;
}

int parse_config(char* config)
{
    char* line = NULL;
    size_t line_len = 0;

    FILE* fp = fopen(config, "r");
    if (fp == NULL)
    {
        print_debug(ERROR, "parse_config fopen %s\n", strerror(errno));
        goto exit;
    }
    int count_str;
    while (getline(&line, &line_len, fp) != EOF)
    {
        // make sure every line has terminated null in the end
        line[strcspn(line, "\r\n")] = '\0';

        if (is_comment(line) == 0 || line[0] == '\0')
        {
            continue;
        }

        char** key_value = split_strings(line, "=", &count_str);
        if (key_value == NULL)
        {
            goto exit_key_value;
        }
        char* key = key_value[0];
        char* value = key_value[1];
        conf_token_t* ct;
        ct = get_config_token(key);
        if (ct != NULL)
        {
            if (set_config_data(ct, value) < 0)
            {
                print_debug(ERROR, "set_config_data crashed\n");
                return -1;
            }
        }
        else
        {
            print_debug(WARN, "token is not found by key %s in line\n", key);
            free_split_strings(key_value, count_str);
            continue;
        }

        free_split_strings(key_value, count_str);
    }

    fclose(fp);
    return 0;

exit:
    return -1;

exit_key_value:
    fclose(fp);
    goto exit;
}

int is_comment(char* line)
{
    char err_msg[MAX_ERR_MSG];
    int err = 0;
    regex_t re;

    err = regcomp(&re, REGEX_COMMENT, REG_EXTENDED | REG_NEWLINE);
    if (err != 0)
    {
        regerror(err, &re, err_msg, MAX_ERR_MSG);
        print_debug(ERROR, "regcomp err %s\n", err_msg);
        return -1;
    }

    size_t nmatch = 1;
    regmatch_t pmatch;
    err = regexec(&re, line, nmatch, &pmatch, 0);
    if (err != 0)
    {
        // line has no comment
        regfree(&re);
        return -1;
    }

    char* start = line + pmatch.rm_so;
    char* end = line + pmatch.rm_eo;
    char str[end - start + 1];
    strncpy(str, start, end - start);
    str[end - start] = '\0';

    regfree(&re);

    return 0;
}

char** split_strings(char* str, char* separators, int* count_strings)
{
    int s_length = strlen(str);
    int i = 0;
    *count_strings = 0;

    while (i < s_length)
    {
        while (i < s_length)
        {
            if (strchr(separators, str[i]) == NULL)
            {
                break;
            }
            i++;
        }

        int j = i;
        while (i < s_length)
        {
            if (strchr(separators, str[i]) != NULL)
            {
                break;
            }
            i++;
        }

        if (j < i)
        {
            *count_strings = *count_strings + 1;
        }
    }

    char** strings = (char**)malloc(sizeof(char*) * (*count_strings));
    if (strings == NULL)
    {
        print_debug(ERROR, "malloc strings: split_strings %s\n",
                    strerror(errno));
        return NULL;
    }

    i = 0;
    int string_index = 0;
    char buf[16384];

    while (i < s_length)
    {
        while (i < s_length)
        {
            if (strchr(separators, str[i]) == NULL)
            {
                break;
            }
            i++;
        }

        int j = 0;
        while (i < s_length)
        {
            if (strchr(separators, str[i]) != NULL)
            {
                break;
            }
            buf[j] = str[i];
            i++;
            j++;
        }

        if (j > 0)
        {
            buf[j] = '\0';

            int to_allocate = sizeof(char) * strlen(buf) + 1;
            strings[string_index] = (char*)malloc(to_allocate);
            if (strings[string_index] == NULL)
            {
                print_debug(ERROR,
                            "malloc strings[string_index]: split_strings %s\n",
                            strerror(errno));
                return NULL;
            }

            strncpy(strings[string_index], buf, j);
            strings[string_index][j] = '\0';
            string_index = string_index + 1;
        }
    }

    return strings;
}

void free_split_strings(char** split_strings, int strings_count)
{
    if (split_strings != NULL)
    {
        for (int i = 0; i < strings_count; ++i)
        {
            free(split_strings[i]);
        }

        free(split_strings);
    }
}

void* config_get_data(conf_type_t conf_type)
{
    switch (conf_type)
    {
        case ROOT:
            return conf_data[ROOT].sval;
        case DEFAULT_FILE:
            return conf_data[DEFAULT_FILE].sval;
        case ADDRESS:
            return conf_data[ADDRESS].sval;
        case HTTP_PORT:
            return &conf_data[HTTP_PORT].nu16val;
        case HTTPS_PORT:
            return &conf_data[HTTPS_PORT].nu16val;
        case CHUNK_ENCODING:
            return &conf_data[CHUNK_ENCODING].nu16val;
        case W3C_FILE:
            return conf_data[W3C_FILE].sval;
        case SSL_KEY:
            return conf_data[SSL_KEY].sval;
        case SSL_CRT:
            return conf_data[SSL_CRT].sval;
        case DEBUG_LVL:
            return &conf_data[DEBUG_LVL].nu16val;
        default:
            print_debug(ERROR, "no config data. Check the config type\n");
            return NULL;
    }
}

conf_token_t* get_config_token(char* str)
{

    for (int i = 0; i < COUNT_TOKENS; i++)
    {
        if (strncmp(conf_data[(conf_type_t)i].name, str, strlen(str)) == 0)
        {
            return &conf_data[(conf_type_t)i];
        }
    }
    return NULL;
}

int set_config_data(conf_token_t* conf_token, char* value)
{
    if (conf_token == NULL || value == NULL)
    {
        print_debug(ERROR, "conf token or value is NULL\n");
        return -1;
    }

    switch (conf_token->type)
    {
        case ROOT:
            if (conf_token->validator(value) < 0)
            {
                return 0;
            }
            strncpy(conf_data[ROOT].sval, value, strlen(value));
            conf_data[ROOT].sval[strlen(value)] = '\0';
            break;
        case HTTP_PORT:
            if (conf_token->validator(value) < 0)
            {
                return 0;
            }
            conf_data[HTTP_PORT].nu16val = (uint16_t)atoi(value);
            break;
        case HTTPS_PORT:
            if (conf_token->validator(value) < 0)
            {
                return 0;
            }
            else
            {
                conf_data[HTTPS_PORT].nu16val = (uint16_t)atoi(value);
            }
            break;
        case ADDRESS:
            if (conf_token->validator(value) < 0)
            {
                return 0;
            }
            strncpy(conf_data[ADDRESS].sval, value, strlen(value));
            conf_data[ADDRESS].sval[strlen(value)] = '\0';
            break;
        case DEFAULT_FILE:
            if (conf_token->validator(value) < 0)
            {
                return 0;
            }
            strncpy(conf_data[DEFAULT_FILE].sval, value, strlen(value));
            conf_data[DEFAULT_FILE].sval[strlen(value)] = '\0';
            break;
        case CHUNK_ENCODING:
            conf_data[CHUNK_ENCODING].nu16val = (int)atoi(value);
            break;
        case W3C_FILE:
            if (conf_token->validator(value) < 0)
            {
                return 0;
            }
            strncpy(conf_data[W3C_FILE].sval, value, strlen(value));
            conf_data[W3C_FILE].sval[strlen(value)] = '\0';
            break;
        case SSL_KEY:
            strncpy(conf_data[SSL_KEY].sval, value, strlen(value));
            conf_data[SSL_KEY].sval[strlen(value)] = '\0';
            break;
        case SSL_CRT:
            strncpy(conf_data[SSL_CRT].sval, value, strlen(value));
            conf_data[SSL_CRT].sval[strlen(value)] = '\0';
            break;
        case DEBUG_LVL:
            if (value == NULL || (strncmp(value, SPACE, strlen(SPACE)) == 0))
            {
                return 0;
            }

            conf_data[DEBUG_LVL].nu16val = (uint8_t)atoi(value);
            break;
        default:
            print_debug(ERROR, "incorrect token\n");
            return -1;
    }
    return 0;
}
