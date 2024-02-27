#ifndef SSL_API_H
#define SSL_API_H

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"

typedef struct MtlsConf
{
    mbedtls_net_context listen_fd;
    mbedtls_net_context client_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
} mtls_conf_t;


typedef struct ConnCtx 
{
    int connfd;
    mtls_conf_t mtls_conf;
    char* ssl_key;
    char* ssl_crt;
    int (*write_fn)(struct ConnCtx* conn_ctx, void* buf, size_t bufsize, uint8_t options );
} conn_ctx_t;

int mtls_init(conn_ctx_t* conn_ctx, char* pers);
int mtls_load_cert(conn_ctx_t* conn_ctx);
void mtls_free(conn_ctx_t* conn_ctx);
int mtls_handshake(conn_ctx_t* conn_ctx);
int mtls_setup(conn_ctx_t* conn_ctx);
void mtls_set_io(conn_ctx_t* conn_ctx);
char* mtls_read_msg(conn_ctx_t* conn_ctx);
int mtls_write_msg(conn_ctx_t* conn_ctx, void* buf, size_t buf_len,
                   uint8_t options);

#endif
