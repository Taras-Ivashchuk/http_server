#include "ssl_api.h"
#include "config_api.h"
#include "logger_api.h"
#include "mbedtls/bignum.h"
#include "mbedtls/cipher.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include <mbedtls/error.h>
#include <stdlib.h>
#include <string.h>

static void my_debug(void* ctx, int level, const char* file, int line,
                     const char* str);

int mtls_init(conn_ctx_t* conn_ctx, char* pers)
{
    int ret = 0;
    char err_buf[MAX_ERR_MSG];

    mbedtls_ssl_config_init(&conn_ctx->mtls_conf.conf);
    mbedtls_ctr_drbg_init(&conn_ctx->mtls_conf.ctr_drbg);
    mbedtls_entropy_init(&conn_ctx->mtls_conf.entropy);
    mbedtls_ssl_init(&conn_ctx->mtls_conf.ssl);
    mbedtls_x509_crt_init(&conn_ctx->mtls_conf.srvcert);
    mbedtls_pk_init(&conn_ctx->mtls_conf.pkey);

    if ((ret = mbedtls_ctr_drbg_seed(
             &conn_ctx->mtls_conf.ctr_drbg, mbedtls_entropy_func,
             &conn_ctx->mtls_conf.entropy, (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        memset(err_buf, 0, MAX_ERR_MSG);
        mbedtls_strerror(ret, err_buf, MAX_ERR_MSG);
        print_debug(ERROR, "mbedtls_ctr_drbg_seed returned %d\n%s\n", ret,
                    err_buf);
        return -1;
    }

    if ((ret = mbedtls_ssl_config_defaults(
             &conn_ctx->mtls_conf.conf, MBEDTLS_SSL_IS_SERVER,
             MBEDTLS_SSL_TRANSPORT_STREAM, 0)) != 0)
    {
        memset(err_buf, 0, MAX_ERR_MSG);
        mbedtls_strerror(ret, err_buf, MAX_ERR_MSG);
        print_debug(ERROR, "mbedtls_ssl_config_defaults returned %d\n%s\n", ret,
                    err_buf);
        return -1;
    }

    mbedtls_ssl_conf_rng(&conn_ctx->mtls_conf.conf, mbedtls_ctr_drbg_random,
                         &conn_ctx->mtls_conf.ctr_drbg);
    mbedtls_ssl_conf_dbg(&conn_ctx->mtls_conf.conf, my_debug, stdout);

    mbedtls_ssl_conf_ca_chain(&conn_ctx->mtls_conf.conf,
                              conn_ctx->mtls_conf.srvcert.next, NULL);

    if ((ret = mbedtls_ssl_conf_own_cert(&conn_ctx->mtls_conf.conf,
                                         &conn_ctx->mtls_conf.srvcert,
                                         &conn_ctx->mtls_conf.pkey)) != 0)
    {
        memset(err_buf, 0, MAX_ERR_MSG);
        mbedtls_strerror(ret, err_buf, MAX_ERR_MSG);
        print_debug(ERROR, "mbedtls_ssl_conf_own_cert returned %d\n%s\n", ret,
                    err_buf);
        return -1;
    }

    return 0;
}

void mtls_free(conn_ctx_t* conn_ctx)
{
    mbedtls_ssl_config_free(&conn_ctx->mtls_conf.conf);
    mbedtls_ctr_drbg_free(&conn_ctx->mtls_conf.ctr_drbg);
    mbedtls_entropy_free(&conn_ctx->mtls_conf.entropy);
    mbedtls_ssl_free(&conn_ctx->mtls_conf.ssl);
    mbedtls_x509_crt_free(&conn_ctx->mtls_conf.srvcert);
    mbedtls_pk_free(&conn_ctx->mtls_conf.pkey);
}

int mtls_handshake(conn_ctx_t* conn_ctx)
{
    int ret = 0;
    char err_buf[MAX_ERR_MSG];

    while ((ret = mbedtls_ssl_handshake(&conn_ctx->mtls_conf.ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            memset(err_buf, 0, MAX_ERR_MSG);
            mbedtls_strerror(ret, err_buf, MAX_ERR_MSG);
            print_debug(ERROR, "handshake returned %d\n%s\n", ret, err_buf);
            return -1;
        }
    }
    return 0;
}

int mtls_setup(conn_ctx_t* conn_ctx)
{
    int ret = 0;
    char* addit = "addit_seed";
    char err_buf[MBEDTLS_MPI_MAX_SIZE];

    if ((ret = mbedtls_ctr_drbg_reseed(&(conn_ctx->mtls_conf.ctr_drbg),
                                       (const unsigned char*)addit,
                                       strlen(addit))) != 0)
    {
        memset(err_buf, 0, MAX_ERR_MSG);
        mbedtls_strerror(ret, err_buf, MAX_ERR_MSG);
        print_debug(ERROR, "mbedtls_ctr_drbg_reseed returned %d\n%s\n", ret,
                    err_buf);
        return -1;
    }

    if ((ret = mbedtls_ssl_setup(&(conn_ctx->mtls_conf.ssl),
                                 &(conn_ctx->mtls_conf.conf))) != 0)
    {
        memset(err_buf, 0, MAX_ERR_MSG);
        mbedtls_strerror(ret, err_buf, MAX_ERR_MSG);
        print_debug(ERROR, "mbedtls_ssl_setup returned %d\n%s\n", ret, err_buf);
        return -1;
    }

    return 0;
}

static void my_debug(void* ctx, int level, const char* file, int line,
                     const char* str)
{
    ((void)level);
    fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE*)ctx);
}

int mtls_load_cert(conn_ctx_t* conn_ctx)
{
    int ret = 0;
    char err_buf[MAX_ERR_MSG];

    ret = mbedtls_x509_crt_parse_file(&conn_ctx->mtls_conf.srvcert,
                                      conn_ctx->ssl_crt);
    if (ret != 0)
    {
        memset(err_buf, 0, MAX_ERR_MSG);
        mbedtls_strerror(ret, err_buf, MAX_ERR_MSG);
        print_debug(ERROR, "mbedtls_x509_crt_parse_file returned %d\n%s\n", ret,
                    err_buf);
        return -1;
    }

    ret = mbedtls_pk_parse_keyfile(&conn_ctx->mtls_conf.pkey, conn_ctx->ssl_key,
                                   NULL, mbedtls_ctr_drbg_random,
                                   &conn_ctx->mtls_conf.ctr_drbg);
    if (ret != 0)
    {
        memset(err_buf, 0, MAX_ERR_MSG);
        mbedtls_strerror(ret, err_buf, MAX_ERR_MSG);
        print_debug(ERROR, "mbedtls_pk_parse_keyfile returned %d\n%s\n", ret,
                    err_buf);
        return -1;
    }

    return 0;
}

void mtls_set_io(conn_ctx_t* conn_ctx)
{
    mbedtls_ssl_set_bio(&conn_ctx->mtls_conf.ssl, &conn_ctx->connfd,
                        mbedtls_net_send, mbedtls_net_recv, NULL);
}

char* mtls_read_msg(conn_ctx_t* conn_ctx)
{
    char buf[MBEDTLS_MPI_MAX_SIZE];
    memset(buf, 0, sizeof(buf));
    int status = 0;
    char err_buf[MAX_ERR_MSG];

    do
    {
        status = mbedtls_ssl_read(&conn_ctx->mtls_conf.ssl, (unsigned char*)buf,
                                  MBEDTLS_MPI_MAX_SIZE - 1);

        if (status == 0)
        {

            break;
        }

        if (status < 0)
        {
            switch (status)
            {
                case MBEDTLS_ERR_SSL_WANT_READ:
                case MBEDTLS_ERR_SSL_WANT_WRITE:
                case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
                case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
                {

                    continue;
                }
                default:
                {
                    mbedtls_strerror(status, err_buf, MAX_ERR_MSG);

                    print_debug(INFO, "<0 read receieved \n %s\n ", err_buf);
                    break;
                }
            }
        }

        break;

    } while (1);

    char* msg = (char*)malloc(strlen(buf) + 1);

    if (msg == NULL)
    {
        print_debug(ERROR, "mtls_read_msg: malloc\n");
        return NULL;
    }

    if (strncpy(msg, buf, strlen(buf)) == NULL)
    {
        print_debug(ERROR, "mtls_read_msg: strncpy\n");
        return NULL;
    }

    msg[strlen(buf)] = '\0';

    return msg;
}

int mtls_write_msg(conn_ctx_t* conn_ctx, void* buf, size_t buf_len,
                   uint8_t options)
{
    int nbytes = 0;
    char err_buf[MAX_ERR_MSG];

    while ((nbytes = mbedtls_ssl_write(&conn_ctx->mtls_conf.ssl,
                                       (unsigned char*)buf, buf_len)) <= 0)
    {
        mbedtls_strerror(nbytes, err_buf, MAX_ERR_MSG);
        if (nbytes == MBEDTLS_ERR_NET_CONN_RESET)
        {
            print_debug(INFO,
                        "mtls_write_msg: peer closed the connection\n\%s\n",
                        err_buf);
            return -1;
        }

        if (nbytes != MBEDTLS_ERR_SSL_WANT_READ &&
            nbytes != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            print_debug(INFO, "mtls_write_msg returned %d\n\%s\n", nbytes,
                        err_buf);
            return -1;
        }
    }

    return nbytes;
}
