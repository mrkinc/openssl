/*
 * Copyright 2016-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;
static unsigned int timer_cb_count;

#define NUM_TESTS 2

#define DUMMY_CERT_STATUS_LEN 12

static unsigned char certstatus[] = {
    SSL3_RT_HANDSHAKE, /* Content type */
    0xfe, 0xfd, /* Record version */
    0, 1, /* Epoch */
    0, 0, 0, 0, 0, 0x0f, /* Record sequence number */
    0, DTLS1_HM_HEADER_LENGTH + DUMMY_CERT_STATUS_LEN - 2,
    SSL3_MT_CERTIFICATE_STATUS, /* Cert Status handshake message type */
    0, 0, DUMMY_CERT_STATUS_LEN, /* Message len */
    0, 5, /* Message sequence */
    0, 0, 0, /* Fragment offset */
    0, 0, DUMMY_CERT_STATUS_LEN - 2, /* Fragment len */
    0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80 /* Dummy data */
};

#define RECORD_SEQUENCE 10

static const char dummy_cookie[] = "0123456";

static int generate_cookie_cb(SSL *ssl, unsigned char *cookie,
    unsigned int *cookie_len)
{
    memcpy(cookie, dummy_cookie, sizeof(dummy_cookie));
    *cookie_len = sizeof(dummy_cookie);
    return 1;
}

static int verify_cookie_cb(SSL *ssl, const unsigned char *cookie,
    unsigned int cookie_len)
{
    return TEST_mem_eq(cookie, cookie_len, dummy_cookie, sizeof(dummy_cookie));
}

static unsigned int timer_cb(SSL *s, unsigned int timer_us)
{
    ++timer_cb_count;

    if (timer_us == 0)
        return 50000;
    else
        return 2 * timer_us;
}

static int test_dtls_unprocessed(int testidx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl1 = NULL, *clientssl1 = NULL;
    BIO *c_to_s_fbio, *c_to_s_mempacket;
    int testresult = 0;

    timer_cb_count = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    c_to_s_fbio = BIO_new(bio_f_tls_dump_filter());
    if (!TEST_ptr(c_to_s_fbio))
        goto end;

    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl1, &clientssl1,
            NULL, c_to_s_fbio)))
        goto end;

    DTLS_set_timer_cb(clientssl1, timer_cb);

    if (testidx == 1)
        certstatus[RECORD_SEQUENCE] = 0xff;

    /*
     * Inject a dummy record from the next epoch. In test 0, this should never
     * get used because the message sequence number is too big. In test 1 we set
     * the record sequence number to be way off in the future.
     */
    c_to_s_mempacket = SSL_get_wbio(clientssl1);
    c_to_s_mempacket = BIO_next(c_to_s_mempacket);
    mempacket_test_inject(c_to_s_mempacket, (char *)certstatus,
        sizeof(certstatus), 1, INJECT_PACKET_IGNORE_REC_SEQ);

    /*
     * Create the connection. We use "create_bare_ssl_connection" here so that
     * we can force the connection to not do "SSL_read" once partly connected.
     * We don't want to accidentally read the dummy records we injected because
     * they will fail to decrypt.
     */
    if (!TEST_true(create_bare_ssl_connection(serverssl1, clientssl1,
            SSL_ERROR_NONE, 0)))
        goto end;

    if (timer_cb_count == 0) {
        printf("timer_callback was not called.\n");
        goto end;
    }

    testresult = 1;
end:
    SSL_free(serverssl1);
    SSL_free(clientssl1);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

/* One record for the cookieless initial ClientHello */
#define CLI_TO_SRV_COOKIE_EXCH 1

/*
 * In a resumption handshake we use 2 records for the initial ClientHello in
 * this test because we are using a very small MTU and the ClientHello is
 * bigger than in the non resumption case.
 */
#define CLI_TO_SRV_RESUME_COOKIE_EXCH 2
#define SRV_TO_CLI_COOKIE_EXCH 1

#define CLI_TO_SRV_EPOCH_0_RECS 3
#define CLI_TO_SRV_EPOCH_1_RECS 1
#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH)
#define SRV_TO_CLI_EPOCH_0_RECS 10
#else
/*
 * In this case we have no ServerKeyExchange message, because we don't have
 * ECDHE or DHE. When it is present it gets fragmented into 3 records in this
 * test.
 */
#define SRV_TO_CLI_EPOCH_0_RECS 9
#endif
#define SRV_TO_CLI_EPOCH_1_RECS 1
#define TOTAL_FULL_HAND_RECORDS \
    (CLI_TO_SRV_COOKIE_EXCH + SRV_TO_CLI_COOKIE_EXCH + CLI_TO_SRV_EPOCH_0_RECS + CLI_TO_SRV_EPOCH_1_RECS + SRV_TO_CLI_EPOCH_0_RECS + SRV_TO_CLI_EPOCH_1_RECS)

#define CLI_TO_SRV_RESUME_EPOCH_0_RECS 3
#define CLI_TO_SRV_RESUME_EPOCH_1_RECS 1
#define SRV_TO_CLI_RESUME_EPOCH_0_RECS 2
#define SRV_TO_CLI_RESUME_EPOCH_1_RECS 1
#define TOTAL_RESUME_HAND_RECORDS \
    (CLI_TO_SRV_RESUME_COOKIE_EXCH + SRV_TO_CLI_COOKIE_EXCH + CLI_TO_SRV_RESUME_EPOCH_0_RECS + CLI_TO_SRV_RESUME_EPOCH_1_RECS + SRV_TO_CLI_RESUME_EPOCH_0_RECS + SRV_TO_CLI_RESUME_EPOCH_1_RECS)

#define TOTAL_RECORDS (TOTAL_FULL_HAND_RECORDS + TOTAL_RESUME_HAND_RECORDS)

/*
 * We are assuming a ServerKeyExchange message is sent in this test. If we don't
 * have either DH or EC, then it won't be
 */
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC)
static int test_dtls_drop_records(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *c_to_s_fbio, *mempackbio;
    int testresult = 0;
    int epoch = 0;
    SSL_SESSION *sess = NULL;
    int cli_to_srv_cookie, cli_to_srv_epoch0, cli_to_srv_epoch1;
    int srv_to_cli_epoch0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifdef OPENSSL_NO_DTLS1_2
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "DEFAULT:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(SSL_CTX_set_dh_auto(sctx, 1)))
        goto end;

    SSL_CTX_set_options(sctx, SSL_OP_COOKIE_EXCHANGE);
    SSL_CTX_set_cookie_generate_cb(sctx, generate_cookie_cb);
    SSL_CTX_set_cookie_verify_cb(sctx, verify_cookie_cb);

    if (idx >= TOTAL_FULL_HAND_RECORDS) {
        /* We're going to do a resumption handshake. Get a session first. */
        if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                SSL_ERROR_NONE))
            || !TEST_ptr(sess = SSL_get1_session(clientssl)))
            goto end;

        SSL_shutdown(clientssl);
        SSL_shutdown(serverssl);
        SSL_free(serverssl);
        SSL_free(clientssl);
        serverssl = clientssl = NULL;

        cli_to_srv_epoch0 = CLI_TO_SRV_RESUME_EPOCH_0_RECS;
        cli_to_srv_epoch1 = CLI_TO_SRV_RESUME_EPOCH_1_RECS;
        srv_to_cli_epoch0 = SRV_TO_CLI_RESUME_EPOCH_0_RECS;
        cli_to_srv_cookie = CLI_TO_SRV_RESUME_COOKIE_EXCH;
        idx -= TOTAL_FULL_HAND_RECORDS;
    } else {
        cli_to_srv_epoch0 = CLI_TO_SRV_EPOCH_0_RECS;
        cli_to_srv_epoch1 = CLI_TO_SRV_EPOCH_1_RECS;
        srv_to_cli_epoch0 = SRV_TO_CLI_EPOCH_0_RECS;
        cli_to_srv_cookie = CLI_TO_SRV_COOKIE_EXCH;
    }

    c_to_s_fbio = BIO_new(bio_f_tls_dump_filter());
    if (!TEST_ptr(c_to_s_fbio))
        goto end;

    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, c_to_s_fbio)))
        goto end;

    if (sess != NULL) {
        if (!TEST_true(SSL_set_session(clientssl, sess)))
            goto end;
    }

    DTLS_set_timer_cb(clientssl, timer_cb);
    DTLS_set_timer_cb(serverssl, timer_cb);

    /* Work out which record to drop based on the test number */
    if (idx >= cli_to_srv_cookie + cli_to_srv_epoch0 + cli_to_srv_epoch1) {
        mempackbio = SSL_get_wbio(serverssl);
        idx -= cli_to_srv_cookie + cli_to_srv_epoch0 + cli_to_srv_epoch1;
        if (idx >= SRV_TO_CLI_COOKIE_EXCH + srv_to_cli_epoch0) {
            epoch = 1;
            idx -= SRV_TO_CLI_COOKIE_EXCH + srv_to_cli_epoch0;
        }
    } else {
        mempackbio = SSL_get_wbio(clientssl);
        if (idx >= cli_to_srv_cookie + cli_to_srv_epoch0) {
            epoch = 1;
            idx -= cli_to_srv_cookie + cli_to_srv_epoch0;
        }
        mempackbio = BIO_next(mempackbio);
    }
    BIO_ctrl(mempackbio, MEMPACKET_CTRL_SET_DROP_EPOCH, epoch, NULL);
    BIO_ctrl(mempackbio, MEMPACKET_CTRL_SET_DROP_REC, idx, NULL);

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    if (sess != NULL && !TEST_true(SSL_session_reused(clientssl)))
        goto end;

    /* If the test did what we planned then it should have dropped a record */
    if (!TEST_int_eq((int)BIO_ctrl(mempackbio, MEMPACKET_CTRL_GET_DROP_REC, 0,
                         NULL),
            -1))
        goto end;

    testresult = 1;
end:
    SSL_SESSION_free(sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif /* !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC) */

static int test_cookie(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

    SSL_CTX_set_options(sctx, SSL_OP_COOKIE_EXCHANGE);
    SSL_CTX_set_cookie_generate_cb(sctx, generate_cookie_cb);
    SSL_CTX_set_cookie_verify_cb(sctx, verify_cookie_cb);

#ifdef OPENSSL_NO_DTLS1_2
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "DEFAULT:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

static int test_dtls_duplicate_records(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifdef OPENSSL_NO_DTLS1_2
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "DEFAULT:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(clientssl, timer_cb);
    DTLS_set_timer_cb(serverssl, timer_cb);

    BIO_ctrl(SSL_get_wbio(clientssl), MEMPACKET_CTRL_SET_DUPLICATE_REC, 1, NULL);
    BIO_ctrl(SSL_get_wbio(serverssl), MEMPACKET_CTRL_SET_DUPLICATE_REC, 1, NULL);

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

/*
 * Test just sending a Finished message as the first message. Should fail due
 * to an unexpected message.
 */
static int test_just_finished(void)
{
    int testresult = 0, ret;
    SSL_CTX *sctx = NULL;
    SSL *serverssl = NULL;
    BIO *rbio = NULL, *wbio = NULL, *sbio = NULL;
    unsigned char buf[] = {
        /* Record header */
        SSL3_RT_HANDSHAKE, /* content type */
        (DTLS1_2_VERSION >> 8) & 0xff, /* protocol version hi byte */
        DTLS1_2_VERSION & 0xff, /* protocol version lo byte */
        0, 0, /* epoch */
        0, 0, 0, 0, 0, 0, /* record sequence */
        0, DTLS1_HM_HEADER_LENGTH + SHA_DIGEST_LENGTH, /* record length */

        /* Message header */
        SSL3_MT_FINISHED, /* message type */
        0, 0, SHA_DIGEST_LENGTH, /* message length */
        0, 0, /* message sequence */
        0, 0, 0, /* fragment offset */
        0, 0, SHA_DIGEST_LENGTH, /* fragment length */

        /* Message body */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            NULL, 0, 0,
            &sctx, NULL, cert, privkey)))
        return 0;

    serverssl = SSL_new(sctx);
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());

    if (!TEST_ptr(serverssl) || !TEST_ptr(rbio) || !TEST_ptr(wbio))
        goto end;

    sbio = rbio;
    SSL_set0_rbio(serverssl, rbio);
    SSL_set0_wbio(serverssl, wbio);
    rbio = wbio = NULL;
    DTLS_set_timer_cb(serverssl, timer_cb);

    if (!TEST_int_eq(BIO_write(sbio, buf, sizeof(buf)), sizeof(buf)))
        goto end;

    /* We expect the attempt to process the message to fail */
    if (!TEST_int_le(ret = SSL_accept(serverssl), 0))
        goto end;

    /* Check that we got the error we were expecting */
    if (!TEST_int_eq(SSL_get_error(serverssl, ret), SSL_ERROR_SSL))
        goto end;

    if (!TEST_int_eq(ERR_GET_REASON(ERR_get_error()), SSL_R_UNEXPECTED_MESSAGE))
        goto end;

    testresult = 1;
end:
    BIO_free(rbio);
    BIO_free(wbio);
    SSL_free(serverssl);
    SSL_CTX_free(sctx);

    return testresult;
}

/*
 * Test that swapping later records before Finished or CCS still works
 * Test 0: Test receiving a handshake record early from next epoch on server side
 * Test 1: Test receiving a handshake record early from next epoch on client side
 * Test 2: Test receiving an app data record early from next epoch on client side
 * Test 3: Test receiving an app data before Finished on client side
 */
static int test_swap_records(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    int testresult = 0;
    BIO *bio;
    char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    char buf[10];

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl,
            NULL, NULL)))
        goto end;

    /* Send flight 1: ClientHello */
    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    /* Recv flight 1, send flight 2: ServerHello, Certificate, ServerHelloDone */
    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    /* Recv flight 2, send flight 3: ClientKeyExchange, CCS, Finished */
    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (idx == 0) {
        /* Swap Finished and CCS within the datagram */
        bio = SSL_get_wbio(cssl);
        if (!TEST_ptr(bio)
            || !TEST_true(mempacket_swap_epoch(bio)))
            goto end;
    }

    /* Recv flight 3, send flight 4: datagram 0(NST, CCS) datagram 1(Finished) */
    if (!TEST_int_gt(SSL_accept(sssl), 0))
        goto end;

    /* Send flight 4 (cont'd): datagram 2(app data) */
    if (!TEST_int_eq(SSL_write(sssl, msg, sizeof(msg)), (int)sizeof(msg)))
        goto end;

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio))
        goto end;
    if (idx == 1) {
        /* Finished comes before NST/CCS */
        if (!TEST_true(mempacket_move_packet(bio, 0, 1)))
            goto end;
    } else if (idx == 2) {
        /* App data comes before NST/CCS */
        if (!TEST_true(mempacket_move_packet(bio, 0, 2)))
            goto end;
    } else if (idx == 3) {
        /* App data comes before Finished */
        bio = SSL_get_wbio(sssl);
        if (!TEST_true(mempacket_move_packet(bio, 1, 2)))
            goto end;
    }

    /*
     * Recv flight 4 (datagram 1): NST, CCS, + flight 5: app data
     *      + flight 4 (datagram 2): Finished
     */
    if (!TEST_int_gt(SSL_connect(cssl), 0))
        goto end;

    if (idx == 0 || idx == 1) {
        /* App data was not received early, so it should not be pending */
        if (!TEST_int_eq(SSL_pending(cssl), 0)
            || !TEST_false(SSL_has_pending(cssl)))
            goto end;

    } else {
        /* We received the app data early so it should be buffered already */
        if (!TEST_int_eq(SSL_pending(cssl), (int)sizeof(msg))
            || !TEST_true(SSL_has_pending(cssl)))
            goto end;
    }

    /*
     * Recv flight 5 (app data)
     */
    if (!TEST_int_eq(SSL_read(cssl, buf, sizeof(buf)), (int)sizeof(msg)))
        goto end;

    testresult = 1;
end:
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return testresult;
}

#ifndef OPENSSL_NO_DTLS1_2
/* A BIO filter that suspends writes after a prescribed number of records. */
typedef struct {
    BIO *bio;
    int allowed;
    int write_calls;
} FRAG_BIO;

static int frag_write(BIO *bio, const char *buf, size_t len, size_t *written)
{
    FRAG_BIO *f = BIO_get_data(bio);

    BIO_clear_retry_flags(bio);
    f->write_calls++;
    if (f->allowed <= 0) {
        BIO_set_retry_write(bio);
        *written = 0;
        return 0;
    }
    f->allowed--;
    return BIO_write_ex(f->bio, buf, len, written);
}

static int frag_read(BIO *bio, char *buf, size_t len, size_t *readbytes)
{
    return BIO_read_ex(((FRAG_BIO *)BIO_get_data(bio))->bio, buf, len,
                       readbytes);
}

static long frag_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    return BIO_ctrl(((FRAG_BIO *)BIO_get_data(bio))->bio, cmd, num, ptr);
}

static int frag_create(BIO *bio)
{
    FRAG_BIO *f = OPENSSL_zalloc(sizeof(*f));

    if (f == NULL)
        return 0;
    BIO_set_data(bio, f);
    BIO_set_init(bio, 1);
    return 1;
}

static int frag_destroy(BIO *bio)
{
    FRAG_BIO *f = BIO_get_data(bio);

    if (f != NULL) {
        BIO_free(f->bio);
        OPENSSL_free(f);
    }
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);
    return 1;
}

static BIO_METHOD *frag_method(void)
{
    static BIO_METHOD *method;

    if (method == NULL) {
        method = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_TYPE_FILTER,
                              "fragment-limited dgram");
        if (method != NULL) {
            BIO_meth_set_write_ex(method, frag_write);
            BIO_meth_set_read_ex(method, frag_read);
            BIO_meth_set_ctrl(method, frag_ctrl);
            BIO_meth_set_create(method, frag_create);
            BIO_meth_set_destroy(method, frag_destroy);
        }
    }
    return method;
}

static BIO *frag_new(BIO *next, int allowed)
{
    BIO *bio = BIO_new(frag_method());
    FRAG_BIO *f;

    if (bio == NULL) {
        BIO_free(next);
        return NULL;
    }
    f = BIO_get_data(bio);
    f->bio = next;
    f->allowed = allowed;
    return bio;
}

/* Wait by polling the DTLS timer.  This avoids a platform-specific sleep API. */
static int wait_for_dtls_timeout(SSL *ssl)
{
    struct timeval tv;
    unsigned int tries = 0;

    do {
        if (DTLSv1_get_timeout(ssl, &tv) <= 0)
            return 0;
        if (++tries == 100000000)
            return 0;
    } while (tv.tv_sec != 0 || tv.tv_usec != 0);
    return 1;
}

/*
 * A ClientHello write is suspended after its first fragment.  Timer-driven
 * retransmission must not touch the retransmit queue or overwrite the parked
 * write state.
 */
static int test_dtls_suspended_write_retransmit(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *underlying = NULL, *wrapped = NULL;
    FRAG_BIO *fb;
    unsigned char alpn[750];
    size_t used = 0, j;
    int ret, err, i, before;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

    for (j = 0; j < 3; j++) {
        char name[250];
        int n = snprintf(name, sizeof(name), "proto-%04u-%s", (unsigned int)j,
                         "padpadpadpadpadpadpadpadpadpadpadpadpadpadpad"
                         "padpadpadpadpadpadpadpadpadpadpadpadpadpadpad"
                         "padpadpadpadpadpadpadpadpadpadpadpadpadpadpad"
                         "padpadpadpadpadpadpadpadpadpadpadpadpadpadpad"
                         "padpadpadpadpadpadpadpadpadpadpadpadpadpadpad");
        if (!TEST_int_ge(n, 0) || !TEST_size_t_lt((size_t)n, sizeof(name))
            || !TEST_size_t_le(used + 1 + (size_t)n, sizeof(alpn)))
            goto end;
        alpn[used++] = (unsigned char)n;
        memcpy(alpn + used, name, (size_t)n);
        used += (size_t)n;
    }
    if (!TEST_false(SSL_CTX_set_alpn_protos(cctx, alpn, (unsigned int)used))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                         NULL, NULL)))
        goto end;

    SSL_set_options(clientssl, SSL_OP_NO_QUERY_MTU);
    if (!TEST_true(SSL_set_mtu(clientssl, 256)))
        goto end;
    underlying = SSL_get_wbio(clientssl);
    if (!TEST_ptr(underlying) || !TEST_true(BIO_up_ref(underlying)))
        goto end;
    wrapped = frag_new(underlying, 1);
    if (!TEST_ptr(wrapped)) {
        underlying = NULL;
        goto end;
    }
    underlying = NULL;
    fb = BIO_get_data(wrapped);
    SSL_set0_wbio(clientssl, wrapped);
    wrapped = NULL;
    DTLS_set_timer_cb(clientssl, timer_cb);

    ret = SSL_connect(clientssl);
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(clientssl, ret), SSL_ERROR_WANT_WRITE))
        goto end;

    fb->allowed = 100;
    for (i = 0; i < 3; i++) {
        before = fb->write_calls;
        if (!TEST_true(wait_for_dtls_timeout(clientssl))
            || !TEST_int_ge(DTLSv1_handle_timeout(clientssl), 0)
            || !TEST_int_eq(fb->write_calls, before))
            goto end;
    }

    ret = SSL_connect(clientssl);
    err = SSL_get_error(clientssl, ret);
    if (!TEST_false(err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL))
        goto end;
    testresult = 1;
end:
    BIO_free(underlying);
    BIO_free(wrapped);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}
#endif

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_dtls_unprocessed, NUM_TESTS);
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC)
    ADD_ALL_TESTS(test_dtls_drop_records, TOTAL_RECORDS);
#endif
    ADD_TEST(test_cookie);
    ADD_TEST(test_dtls_duplicate_records);
    ADD_TEST(test_just_finished);
    ADD_ALL_TESTS(test_swap_records, 4);
#ifndef OPENSSL_NO_DTLS1_2
    ADD_TEST(test_dtls_suspended_write_retransmit);
#endif

    return 1;
}

void cleanup_tests(void)
{
    bio_f_tls_dump_filter_free();
    bio_s_mempacket_test_free();
}
