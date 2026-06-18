// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// Unit tests for mq_ignore_hosts — the MITM "leave-this-flow-opaque" host list.
// Entries are normalized with the list's OWN rules (lowercase + single
// trailing-dot strip, leading '.' PRESERVED as the suffix marker). The SNI
// passed to match() is ALREADY mq_mitm_normalize_sni-normalized by the caller
// (lowercase, no leading/trailing dot), so match() only compares.
#include "mqtest.h"
#include "mitm/mq_ignore_hosts.h"
#include <stddef.h>

static void
test_basic_exact_and_suffix(void)
{
    mq_ignore_hosts_t *l = mq_ignore_hosts_new();
    MQ_CHECK(l != NULL);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_add(l, ".apple.com"), 0);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_add(l, "signal.org"), 0);

    // Leading-dot entry ".apple.com" = all subdomains, NOT the apex.
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "gateway.apple.com"), 1);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "a.b.apple.com"), 1);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "apple.com"), 0);
    // "notapple.com" ends with "apple.com" but the char before is 't', not '.'
    // — the ".apple.com" suffix must NOT match.
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "notapple.com"), 0);

    // Exact entry "signal.org" = apex only.
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "signal.org"), 1);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "m.signal.org"), 0);

    // SIGNAL.ORG: the caller normalizes to "signal.org" before calling match.
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "signal.org"), 1);

    mq_ignore_hosts_free(l);
}

static void
test_empty_list(void)
{
    mq_ignore_hosts_t *l = mq_ignore_hosts_new();
    MQ_CHECK(l != NULL);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "anything.example"), 0);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, ""), 0);
    mq_ignore_hosts_free(l);
}

static void
test_normalization(void)
{
    mq_ignore_hosts_t *l = mq_ignore_hosts_new();
    MQ_CHECK(l != NULL);
    // Uppercase entry is lowercased on add; matched against normalized SNI.
    MQ_CHECK_EQ_INT(mq_ignore_hosts_add(l, "EXAMPLE.COM"), 0);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "example.com"), 1);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "EXAMPLE.COM"),
                    0); // caller passes lowercase

    // Trailing dot on an exact entry is stripped → matches dot-free SNI.
    MQ_CHECK_EQ_INT(mq_ignore_hosts_add(l, "trailing.test."), 0);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "trailing.test"), 1);

    // Trailing dot on a leading-dot entry: ".sub.test." → ".sub.test".
    MQ_CHECK_EQ_INT(mq_ignore_hosts_add(l, ".SUB.TEST."), 0);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "x.sub.test"), 1);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "sub.test"), 0);

    mq_ignore_hosts_free(l);
}

static void
test_invalid_inputs(void)
{
    mq_ignore_hosts_t *l = mq_ignore_hosts_new();
    MQ_CHECK(l != NULL);
    MQ_CHECK(mq_ignore_hosts_add(l, NULL) < 0);
    MQ_CHECK(mq_ignore_hosts_add(l, "") < 0);
    // A bare "." (just a leading-dot marker with no host) is invalid.
    MQ_CHECK(mq_ignore_hosts_add(l, ".") < 0);
    // Over-long pattern is rejected.
    char big[512];
    for (size_t i = 0; i < sizeof(big) - 1; i++)
        big[i] = 'a';
    big[sizeof(big) - 1] = '\0';
    MQ_CHECK(mq_ignore_hosts_add(l, big) < 0);

    // NULL list / NULL sni are safe (no match, no crash).
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(NULL, "x"), 0);
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, NULL), 0);

    mq_ignore_hosts_free(l);
    mq_ignore_hosts_free(NULL); // free(NULL) is a no-op
}

static void
test_full_list(void)
{
    mq_ignore_hosts_t *l = mq_ignore_hosts_new();
    MQ_CHECK(l != NULL);
    char host[64];
    int added = 0;
    for (int i = 0; i < MQ_IGNORE_HOSTS_MAX; i++) {
        snprintf(host, sizeof(host), "host%d.test", i);
        if (mq_ignore_hosts_add(l, host) == 0) added++;
    }
    MQ_CHECK_EQ_INT(added, MQ_IGNORE_HOSTS_MAX);
    // One more must be rejected (list full).
    MQ_CHECK(mq_ignore_hosts_add(l, "overflow.test") < 0);
    // The entries that did fit still match.
    MQ_CHECK_EQ_INT(mq_ignore_hosts_match(l, "host0.test"), 1);
    mq_ignore_hosts_free(l);
}

MQ_TEST_MAIN(test_basic_exact_and_suffix(); test_empty_list(); test_normalization();
             test_invalid_inputs(); test_full_list();)
