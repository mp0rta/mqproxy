/* test_path_bind.c — Task 9 smoke test.
 *
 * Opens an mq_path on 127.0.0.1:0 against a client-mode engine, checks the fd
 * is valid and an ephemeral port was assigned, then closes everything cleanly
 * (ASan-clean: read event freed, fd closed, struct freed, engine torn down).
 */
#include "mqtest.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include "transport/mq_engine.h"
#include "transport/mq_path.h"

static uint16_t
port_of(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *)ss)->sin_port);
    }
    if (ss->ss_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)ss)->sin6_port);
    }
    return 0;
}

static void
test_path_bind(void)
{
    mq_engine_t *e = mq_engine_new(/*is_server=*/0, /*base=*/NULL);
    MQ_CHECK(e != NULL);
    if (!e) return;

    mq_path_t *p = mq_path_open(e, /*path_id=*/0, "127.0.0.1", /*port=*/0);
    MQ_CHECK(p != NULL);
    if (p) {
        MQ_CHECK(mq_path_fd(p) >= 0);
        MQ_CHECK_EQ_INT(mq_path_id(p), 0);

        struct sockaddr_storage ss;
        socklen_t len = 0;
        MQ_CHECK_EQ_INT(mq_path_local_addr(p, &ss, &len), 0);
        MQ_CHECK(len > 0);
        MQ_CHECK(ss.ss_family == AF_INET);
        MQ_CHECK(port_of(&ss) != 0); /* ephemeral port assigned */

        /* Bad-address path returns NULL without leaking. */
        mq_path_t *bad = mq_path_open(e, 1, "not-an-ip", 0);
        MQ_CHECK(bad == NULL);

        mq_path_close(p);
    }

    mq_engine_free(e);
}

MQ_TEST_MAIN(test_path_bind())
