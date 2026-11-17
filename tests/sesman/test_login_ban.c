/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 *
 * @file test_login_ban.c
 * @brief Tests for the failed login IP blocking table
 *
 * Time is passed in to the module, so these tests use a fake clock
 * rather than sleeping.
 *
 */

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#include <stdio.h>

#include "login_ban.h"

#include "test_sesman.h"

/* Settings used by most tests: block after 3 failures in 60 seconds,
 * for 100 seconds */
static const struct login_ban_config g_cfg = { 3, 60, 100 };

/* A starting time. Any value works */
#define T0 ((time_t)1700000000)

static struct login_ban *g_ban = NULL;

/******************************************************************************/
static void
setup(void)
{
    g_ban = login_ban_create(0);
    ck_assert_ptr_nonnull(g_ban);
}

/******************************************************************************/
static void
teardown(void)
{
    login_ban_delete(g_ban);
    g_ban = NULL;
}

/******************************************************************************/
/* Fail n times from ip at time t. Returns the result of the last call */
static int
fail_n(const char *ip, unsigned int n, time_t t)
{
    int rv = 0;
    unsigned int i;
    for (i = 0 ; i < n ; ++i)
    {
        rv = login_ban_record_failure(g_ban, &g_cfg, ip, t);
    }
    return rv;
}

/******************************************************************************/
START_TEST(test_normalise__ipv4)
{
    char buff[LOGIN_BAN_IP_LEN];
    ck_assert_int_eq(login_ban_normalise_ip("192.168.0.20", buff,
                                            sizeof(buff)), 0);
    ck_assert_str_eq(buff, "192.168.0.20");
}
END_TEST

/******************************************************************************/
START_TEST(test_normalise__mapped_ipv4)
{
    char buff[LOGIN_BAN_IP_LEN];
    ck_assert_int_eq(login_ban_normalise_ip("::ffff:127.0.0.1", buff,
                                            sizeof(buff)), 0);
    ck_assert_str_eq(buff, "127.0.0.1");
}
END_TEST

/******************************************************************************/
START_TEST(test_normalise__ipv6_canonical)
{
    char buff[LOGIN_BAN_IP_LEN];
    /* Different spellings of one address give the same result */
    ck_assert_int_eq(login_ban_normalise_ip("2001:DB8:0:0:0:0:0:1", buff,
                                            sizeof(buff)), 0);
    ck_assert_str_eq(buff, "2001:db8::1");
}
END_TEST

/******************************************************************************/
START_TEST(test_normalise__invalid)
{
    char buff[LOGIN_BAN_IP_LEN];
    ck_assert_int_ne(login_ban_normalise_ip("", buff, sizeof(buff)), 0);
    ck_assert_int_ne(login_ban_normalise_ip("unknown", buff, sizeof(buff)), 0);
    ck_assert_int_ne(login_ban_normalise_ip("1.2.3.4:3389", buff,
                                            sizeof(buff)), 0);
    ck_assert_int_ne(login_ban_normalise_ip("999.1.1.1", buff,
                                            sizeof(buff)), 0);
    ck_assert_int_ne(login_ban_normalise_ip(NULL, buff, sizeof(buff)), 0);
}
END_TEST

/******************************************************************************/
START_TEST(test_ban__disabled)
{
    static const struct login_ban_config off = { 0, 60, 100 };
    unsigned int i;

    for (i = 0 ; i < 50 ; ++i)
    {
        ck_assert_int_eq(login_ban_record_failure(g_ban, &off, "10.0.0.1",
                         T0), 0);
    }
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &off, "10.0.0.1", T0, NULL),
                     0);
    /* Nothing is stored when the feature is off */
    ck_assert_int_eq(login_ban_get_count(g_ban), 0);
}
END_TEST

/******************************************************************************/
START_TEST(test_ban__below_threshold)
{
    ck_assert_int_eq(fail_n("10.0.0.1", 2, T0), 0);
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &g_cfg, "10.0.0.1", T0, NULL),
                     0);
}
END_TEST

/******************************************************************************/
START_TEST(test_ban__at_threshold)
{
    unsigned int remaining = 0;

    ck_assert_int_eq(fail_n("10.0.0.1", 3, T0), 1);
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &g_cfg, "10.0.0.1",
                                          T0 + 10, &remaining), 1);
    ck_assert_uint_eq(remaining, 90);
}
END_TEST

/******************************************************************************/
START_TEST(test_ban__addresses_independent)
{
    ck_assert_int_eq(fail_n("10.0.0.1", 3, T0), 1);
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &g_cfg, "10.0.0.2", T0, NULL),
                     0);
    ck_assert_int_eq(fail_n("10.0.0.2", 2, T0), 0);
}
END_TEST

/******************************************************************************/
/* An attacker can't avoid the block by switching address formats */
START_TEST(test_ban__mapped_address_same_key)
{
    ck_assert_int_eq(fail_n("127.0.0.1", 2, T0), 0);
    ck_assert_int_eq(fail_n("::ffff:127.0.0.1", 1, T0), 1);
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &g_cfg, "127.0.0.1", T0, NULL),
                     1);
    ck_assert_uint_eq(login_ban_get_count(g_ban), 1);
}
END_TEST

/******************************************************************************/
START_TEST(test_ban__expires)
{
    ck_assert_int_eq(fail_n("10.0.0.1", 3, T0), 1);
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &g_cfg, "10.0.0.1",
                                          T0 + 99, NULL), 1);
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &g_cfg, "10.0.0.1",
                                          T0 + 100, NULL), 0);

    /* After the block, the count starts again */
    ck_assert_int_eq(fail_n("10.0.0.1", 2, T0 + 100), 0);
    ck_assert_int_eq(fail_n("10.0.0.1", 1, T0 + 100), 1);
}
END_TEST

/******************************************************************************/
/* Failures spread out over more than the window don't add up */
START_TEST(test_ban__window_expires)
{
    ck_assert_int_eq(fail_n("10.0.0.1", 2, T0), 0);
    /* 60 seconds later, the window has passed */
    ck_assert_int_eq(fail_n("10.0.0.1", 2, T0 + 60), 0);
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &g_cfg, "10.0.0.1",
                                          T0 + 60, NULL), 0);
    /* ...but a third failure in the new window blocks */
    ck_assert_int_eq(fail_n("10.0.0.1", 1, T0 + 61), 1);
}
END_TEST

/******************************************************************************/
/* Failures while blocked don't make the block longer */
START_TEST(test_ban__not_extended)
{
    unsigned int remaining = 0;

    ck_assert_int_eq(fail_n("10.0.0.1", 3, T0), 1);
    ck_assert_int_eq(fail_n("10.0.0.1", 5, T0 + 50), 1);
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &g_cfg, "10.0.0.1",
                                          T0 + 50, &remaining), 1);
    ck_assert_uint_eq(remaining, 50);
}
END_TEST

/******************************************************************************/
START_TEST(test_ban__success_resets)
{
    ck_assert_int_eq(fail_n("10.0.0.1", 2, T0), 0);
    login_ban_record_success(g_ban, "::ffff:10.0.0.1");
    ck_assert_uint_eq(login_ban_get_count(g_ban), 0);
    ck_assert_int_eq(fail_n("10.0.0.1", 2, T0), 0);
}
END_TEST

/******************************************************************************/
START_TEST(test_ban__invalid_ip_ignored)
{
    ck_assert_int_eq(fail_n("", 10, T0), 0);
    ck_assert_int_eq(fail_n("unknown", 10, T0), 0);
    ck_assert_uint_eq(login_ban_get_count(g_ban), 0);
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &g_cfg, "", T0, NULL), 0);
}
END_TEST

/******************************************************************************/
/* Settings are read on every call, so a config reload works at once */
START_TEST(test_ban__settings_change)
{
    static const struct login_ban_config strict = { 1, 60, 100 };
    static const struct login_ban_config off = { 0, 60, 100 };

    ck_assert_int_eq(fail_n("10.0.0.1", 1, T0), 0);
    ck_assert_int_eq(login_ban_record_failure(g_ban, &strict, "10.0.0.1",
                     T0), 1);
    /* Turning the feature off unblocks everyone */
    ck_assert_int_eq(login_ban_is_blocked(g_ban, &off, "10.0.0.1", T0, NULL),
                     0);
}
END_TEST

/******************************************************************************/
/* The table can't grow without limit */
START_TEST(test_table__full_evicts_oldest)
{
    struct login_ban *small = login_ban_create(3);
    char ip[32];
    unsigned int i;

    ck_assert_ptr_nonnull(small);
    for (i = 1 ; i <= 3 ; ++i)
    {
        snprintf(ip, sizeof(ip), "10.0.0.%u", i);
        login_ban_record_failure(small, &g_cfg, ip, T0 + i);
    }
    ck_assert_uint_eq(login_ban_get_count(small), 3);

    /* A fourth address pushes out the oldest (10.0.0.1) */
    login_ban_record_failure(small, &g_cfg, "10.0.0.4", T0 + 10);
    ck_assert_uint_eq(login_ban_get_count(small), 3);

    /* 10.0.0.1 has been forgotten, so it needs 3 more failures */
    ck_assert_int_eq(login_ban_record_failure(small, &g_cfg, "10.0.0.1",
                     T0 + 11), 0);
    ck_assert_uint_eq(login_ban_get_count(small), 3);

    login_ban_delete(small);
}
END_TEST

/******************************************************************************/
/* Expired entries are removed before active ones */
START_TEST(test_table__full_evicts_expired_first)
{
    struct login_ban *small = login_ban_create(2);
    ck_assert_ptr_nonnull(small);

    /* An active block, and an old failure whose window has passed */
    ck_assert_int_eq(login_ban_record_failure(small, &g_cfg, "10.0.0.1", T0),
                     0);
    ck_assert_int_eq(login_ban_record_failure(small, &g_cfg, "10.0.0.2",
                     T0 + 50), 0);
    login_ban_record_failure(small, &g_cfg, "10.0.0.2", T0 + 50);
    ck_assert_int_eq(login_ban_record_failure(small, &g_cfg, "10.0.0.2",
                     T0 + 50), 1);

    /* At T0+70, 10.0.0.1's window has expired, but 10.0.0.2 is still
     * blocked, even though its last failure is newer. 10.0.0.1 goes */
    login_ban_record_failure(small, &g_cfg, "10.0.0.3", T0 + 70);
    ck_assert_int_eq(login_ban_is_blocked(small, &g_cfg, "10.0.0.2",
                                          T0 + 70, NULL), 1);

    login_ban_delete(small);
}
END_TEST

/******************************************************************************/
/* Many different addresses, as an attacker might send */
START_TEST(test_table__many_addresses)
{
    struct login_ban *t = login_ban_create(0);
    char ip[32];
    unsigned int i;

    ck_assert_ptr_nonnull(t);
    for (i = 0 ; i < LOGIN_BAN_DEFAULT_MAX_ENTRIES * 2 ; ++i)
    {
        snprintf(ip, sizeof(ip), "10.%u.%u.%u",
                 (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        login_ban_record_failure(t, &g_cfg, ip, T0);
    }
    ck_assert_uint_eq(login_ban_get_count(t), LOGIN_BAN_DEFAULT_MAX_ENTRIES);
    login_ban_delete(t);
}
END_TEST

/******************************************************************************/
Suite *
make_suite_test_login_ban(void)
{
    Suite *s;
    TCase *tc;

    s = suite_create("LoginBan");

    tc = tcase_create("normalise");
    tcase_add_test(tc, test_normalise__ipv4);
    tcase_add_test(tc, test_normalise__mapped_ipv4);
    tcase_add_test(tc, test_normalise__ipv6_canonical);
    tcase_add_test(tc, test_normalise__invalid);
    suite_add_tcase(s, tc);

    tc = tcase_create("ban");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_ban__disabled);
    tcase_add_test(tc, test_ban__below_threshold);
    tcase_add_test(tc, test_ban__at_threshold);
    tcase_add_test(tc, test_ban__addresses_independent);
    tcase_add_test(tc, test_ban__mapped_address_same_key);
    tcase_add_test(tc, test_ban__expires);
    tcase_add_test(tc, test_ban__window_expires);
    tcase_add_test(tc, test_ban__not_extended);
    tcase_add_test(tc, test_ban__success_resets);
    tcase_add_test(tc, test_ban__invalid_ip_ignored);
    tcase_add_test(tc, test_ban__settings_change);
    suite_add_tcase(s, tc);

    tc = tcase_create("table");
    tcase_add_test(tc, test_table__full_evicts_oldest);
    tcase_add_test(tc, test_table__full_evicts_expired_first);
    tcase_add_test(tc, test_table__many_addresses);
    suite_add_tcase(s, tc);

    return s;
}
