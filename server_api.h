#ifndef SERVER_API_H
#define SERVER_API_H

#include "ssl_api.h"
#include <stdint.h>
#include <sys/socket.h>

#define IP_VERSION AF_INET
#define TRANSPORT_PROTOCOL SOCK_STREAM
#define HTTP_SRV_OPT_KEEP_ALIVE 0x01
#define HTTP_SRV_OPT_TE_CHUNKED 0x02
#define TIMEOUT_DEFAULT_SEC 10

typedef int (*start_server_t)(char* address, uint_least16_t port,
                              char* root_folder, char* default_file,
                              char* msg_log_file);
int create_socket();
int bind_socket(int sockfd, char* address, uint16_t port);
int listen_connection(int sockfd);
int accept_connection(int sockfd);
int start_http_server(char* address, uint16_t port, char* root_folder,
                      char* default_file, char* msg_log_file, char* ssl_key, char* ssl_crt);
int start_https_server(char* address, uint16_t port, char* root_folder,
                       char* default_file, char* msg_log_file);
void set_root_folder(char* root_folder);

#endif
