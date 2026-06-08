// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
/* test_metrics_format.c — Phase 5c: pure logfmt formatters. No I/O. */
#include "mqtest.h"
#include <string.h>
#include <xquic/xquic.h>
#include "transport/mq_conn.h"

static void
test_path_line(void)
{
    xqc_path_metrics_t p;
    memset(&p, 0, sizeof(p));
    p.path_id = 1;
    p.path_state = 2;        /* ACTIVE */
    p.path_srtt = 12345;     /* usec -> 12 ms (integer division) */
    p.path_est_bw = 6029312; /* bytes/sec */
    p.path_send_bytes = 1287654;
    p.path_recv_bytes = 83120;
    p.path_lost_count = 14;

    char buf[MQ_METRICS_LINE_CAP];
    int n = mq_conn_format_path_line(buf, sizeof(buf), &p);
    MQ_CHECK(n > 0);
    MQ_CHECK(strcmp(buf, "mq.path id=1 state=2 srtt_ms=12 bw_Bps=6029312 "
                         "sent=1287654 recv=83120 lost=14") == 0);
}

static void
test_conn_line(void)
{
    xqc_conn_stats_t st;
    memset(&st, 0, sizeof(st));
    st.mp_state = 1;
    st.paths_info_count = 2;
    st.total_app_bytes = 1320044;
    st.standby_path_app_bytes = 0;

    char buf[MQ_METRICS_LINE_CAP];
    int n = mq_conn_format_conn_line(buf, sizeof(buf), &st);
    MQ_CHECK(n > 0);
    MQ_CHECK(
        strcmp(buf, "mq.conn mp_state=1 paths=2 app_bytes=1320044 standby_bytes=0") == 0);
}

static void
test_truncation(void)
{
    xqc_path_metrics_t p;
    memset(&p, 0, sizeof(p));
    p.path_id = 1;
    char tiny[8];
    /* Too small to hold the line -> snprintf truncates -> return -1. */
    MQ_CHECK_EQ_INT(mq_conn_format_path_line(tiny, sizeof(tiny), &p), -1);
}

static void
test_metrics_format(void)
{
    test_path_line();
    test_conn_line();
    test_truncation();
}

MQ_TEST_MAIN(test_metrics_format())
