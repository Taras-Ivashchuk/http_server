#include "server_api.h"
#include "config_api.h"
#include "http_api.h"
#include "logger_api.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern char* msg_log_fields[];
extern uint8_t g_is_https;

struct sockaddr_in saddr_g;
socklen_t saddr_len_g = sizeof(saddr_g);

int create_socket()
{
    int listenfd = socket(IP_VERSION, TRANSPORT_PROTOCOL, 0);
    if (listenfd < 0)
    {
        print_debug(ERROR, "create_socket %s\n", strerror(errno));
        return -1;
    }

    print_debug(INFO, "socket created\n");

    return listenfd;
}

int bind_socket(int listenfd, char* address, uint16_t port)
{
    saddr_g.sin_port = htons(port);
    saddr_g.sin_family = IP_VERSION;
    int s = inet_pton(AF_INET, address, &saddr_g.sin_addr.s_addr);
    if (s == 0)
    {
        print_debug(ERROR, "bind_socket: inet_pton %s\n", strerror(errno));
        return -1;
    }
    if (s < 0)
    {
        print_debug(ERROR, "bind_socket: inet_pton %s\n", strerror(errno));
        return -1;
    }

    if (bind(listenfd, (struct sockaddr*)&saddr_g, saddr_len_g) < 0)
    {
        print_debug(ERROR, "bind_socket %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int listen_connection(int listenfd)
{
    if (listen(listenfd, SOMAXCONN) < 0)
    {
        print_debug(ERROR, "listen %s\n", strerror(errno));
        return -1;
    }

    print_debug(INFO, "server is listening...\n");

    return 0;
}

int accept_connection(int listenfd)
{
    int connfd = accept(listenfd, (struct sockaddr*)&saddr_g, &saddr_len_g);
    if (connfd < 0)
    {
        print_debug(ERROR, "accept %s\n", strerror(errno));
        return -1;
    }

    return connfd;
}

void set_root_folder(char* root_folder)
{
    chdir(root_folder);
    if (chroot(root_folder) < 0)
    {
        print_debug(ERROR, "chroot %s\n", strerror(errno));
        print_debug(ERROR, "Have you tried running this as root?\n");
        return;
    }
}

int start_http_server(char* s_ip, uint16_t port, char* root_folder,
                      char* default_file, char* msg_log_file, char* ssl_key,
                      char* ssl_crt)
{
    pid_t pid = -1;
    uint8_t http_srv_options = 0;

    FILE* msg_log_fp = NULL;

    if (strncmp(msg_log_file, W3C_FILE_DEFAULT, strlen(W3C_FILE_DEFAULT)) == 0)
    {
        msg_log_fp = stdout;
    }
    else
    {
        msg_log_fp = fopen(msg_log_file, "w");
    }

    conn_ctx_t conn_ctx;
    conn_ctx.ssl_key = ssl_key;
    conn_ctx.ssl_crt = ssl_crt;
    conn_ctx.write_fn = &write_mes;

    if (g_is_https)
    {
        conn_ctx.write_fn = &mtls_write_msg;
        char* pers = "my_pers";
        if (mtls_init(&conn_ctx, pers) < 0)
        {
            return -1;
        }

        if (mtls_load_cert(&conn_ctx) < 0)
        {
            return -1;
        }
    }

    set_root_folder(root_folder);

    int listenfd = create_socket();
    if (listenfd < 0)
    {
        return -1;
    }

    if (bind_socket(listenfd, s_ip, port) < 0)
    {
        return -1;
    }

    if (listen_connection(listenfd) < 0)
    {
        return -1;
    }

    char header_buf[HDR_BUF_LENGTH];
    float log_version = 1.0f;
    construct_msg_log_header(header_buf, HDR_BUF_LENGTH, log_version,
                             msg_log_fields, DATE_OPTION | SOFTWARE_OPTION);

    msg_log(msg_log_fp, header_buf, 0);
    fflush(msg_log_fp);

    print_debug(INFO, g_is_https ? "https server started\n"
                                 : "http server started\n");

    while (1)
    {
        int retval = -1;
        if ((retval = accept_connection(listenfd)) < 0)
        {
            return -1;
        }

        conn_ctx.connfd = retval;

        print_debug(INFO, "accepted connection\n");

        struct sockaddr_in* sa = (struct sockaddr_in*)&saddr_g;
        in_addr_t nc_ip = sa->sin_addr.s_addr;
        char c_ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &nc_ip, c_ip, INET6_ADDRSTRLEN) == NULL)
        {
            print_debug(ERROR, "c_ip: inet_ntop %s\n", strerror(errno));
            return -1;
        }

        if ((pid = fork()) == 0)

	{
            close(listenfd);
            int is_timer_set = 0;
            struct timeval tv;
            tv.tv_usec = 0;
            tv.tv_sec = 0;

            if (g_is_https)
            {
                if (mtls_setup(&conn_ctx) < 0)
                {
                    return -1;
                }

                mtls_set_io(&conn_ctx);

                if (mtls_handshake(&conn_ctx) < 0)
                {
                    return -1;
                }
            }

            do
            {
                if (handle_clt(&conn_ctx, default_file, s_ip, c_ip, msg_log_fp,
                               &http_srv_options) < 0)
                {
                    print_debug(INFO, "client not handled\n");

                    if (errno == EAGAIN || errno == EWOULDBLOCK ||
                        errno == EPIPE || errno == ENOENT)
                    {
                        print_debug(INFO, "timed out with errno #%i\n", errno);
                        print_debug(INFO, "error %s\n", strerror(errno));
                        is_timer_set = 0;
                        break;
                    }
                }

                // if (http_srv_options & HTTP_SRV_OPT_KEEP_ALIVE)
                // {
                //     tv.tv_sec = TIMEOUT_DEFAULT_SEC;
                //     if (setsockopt(conn_ctx.connfd, SOL_SOCKET, SO_RCVTIMEO,
                //     (struct timeval*)&tv,
                //                    sizeof(struct timeval)) == -1)
                //     {
                //         perror("setsockopt timeout");
                //         print_debug(ERROR, "timer not set\n");
                //         return -1;
                //     }

                //     is_timer_set = 1;
                //     print_debug(INFO, "timer set in %i seconds\n",
                //                 TIMEOUT_DEFAULT_SEC);

                //     http_srv_options &= (~HTTP_SRV_OPT_KEEP_ALIVE);
                // }

            } while (is_timer_set);

            print_debug(INFO, "timer unset after %i seconds\n",
                        TIMEOUT_DEFAULT_SEC);

            if (g_is_https)
            {
                mtls_free(&conn_ctx);
            }
            else
            {
                close(conn_ctx.connfd);
            }

            print_debug(INFO, "child killed\n");
            exit(EXIT_SUCCESS);
        }

        close(conn_ctx.connfd);
    }

    close(listenfd);

    if (msg_log_fp != NULL)
    {
        fclose(msg_log_fp);
    }
    return 0;
}
