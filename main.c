#include "config_api.h"
#include "logger_api.h"
#include "server_api.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

extern uint8_t debug_lvl;
uint8_t g_is_https = 1;

void reap_children()
{
    while (1)
    {
        pid_t pid = waitpid(-1, NULL, WNOHANG);
        if (pid <= 0)
        {
            break;
        }
    }
}

int main(int argc, char* argv[])
{
    char* config = "config.ini";
    uint16_t port = 0;
    char* address = NULL;
    char* default_file = NULL;
    char* root_dir = NULL;
    char* msg_log_file = NULL;
    char* ssl_key = NULL;
    char* ssl_crt = NULL;

    if (parse_config(config) < 0)
    {
        print_debug(ERROR, "error parsing the config data\n");
        return -1;
    }

    port = (*(uint16_t*)config_get_data(HTTPS_PORT));
    address = (char*)config_get_data(ADDRESS);
    root_dir = (char*)config_get_data(ROOT);
    default_file = (char*)config_get_data(DEFAULT_FILE);
    debug_lvl = (*(uint8_t*)config_get_data(DEBUG_LVL));
    msg_log_file = (char*)config_get_data(W3C_FILE);
    ssl_key = (char*)config_get_data(SSL_KEY);
    ssl_crt = (char*)config_get_data(SSL_CRT);

    if (argc > 1)
    {
        char* last_4_chars = argv[1] + (strlen(argv[1]) - 4);
        if (strncmp(last_4_chars, "http", 4) == 0)
        {
            port = (*(uint16_t*)config_get_data(HTTP_PORT));
            g_is_https = 0;
        }
    }

    signal(SIGCHLD, reap_children);

    if (start_http_server(address, port, root_dir, default_file, msg_log_file,
                          ssl_key, ssl_crt) < 0)
    {
        return -1;
    }

    return 0;
}
