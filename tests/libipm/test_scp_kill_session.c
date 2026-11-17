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
 * @file test_scp_kill_session.c
 * @brief Tests for the SCP kill session messages
 *
 */

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#include <limits.h>

#include "libipm.h"
#include "os_calls.h"
#include "scp.h"
#include "scp_sync.h"
#include "string_calls.h"
#include "trans.h"

#include "test_libipm.h"

/* A pair of connected SCP transports. Messages sent on one can be
 * read on the other */
static struct trans *g_client = NULL;
static struct trans *g_server = NULL;

/******************************************************************************/
static struct trans *
make_scp_trans(int sck, int type)
{
    struct trans *t = trans_create(TRANS_MODE_UNIX, 128, 128);
    if (t != NULL)
    {
        t->sck = sck;
        t->type1 = type;
        t->status = TRANS_STATUS_UP;
        if (scp_init_trans(t) != 0)
        {
            trans_delete(t);
            t = NULL;
        }
    }
    return t;
}

/******************************************************************************/
static void
setup(void)
{
    int sck[2];

    ck_assert_int_eq(g_sck_local_socketpair(sck), 0);
    g_client = make_scp_trans(sck[0], TRANS_TYPE_CLIENT);
    g_server = make_scp_trans(sck[1], TRANS_TYPE_SERVER);
    ck_assert_ptr_nonnull(g_client);
    ck_assert_ptr_nonnull(g_server);
}

/******************************************************************************/
static void
teardown(void)
{
    trans_delete(g_client);
    trans_delete(g_server);
    g_client = NULL;
    g_server = NULL;
}

/******************************************************************************/
/* Waits for the next message on a transport and checks its number */
static void
expect_message(struct trans *t, enum scp_msg_code expected)
{
    ck_assert_int_eq(scp_msg_in_wait_available(t), 0);
    ck_assert_int_eq(scp_msg_in_get_msgno(t), expected);
}

/******************************************************************************/
START_TEST(test_kill_request__round_trip)
{
    static const int sids[] = { 1, 1234, 65535, INT_MAX };
    unsigned int i;

    for (i = 0 ; i < sizeof(sids) / sizeof(sids[0]); ++i)
    {
        int sid = -1;

        ck_assert_int_eq(scp_send_kill_session_request(g_client, sids[i]), 0);
        expect_message(g_server, E_SCP_KILL_SESSION_REQUEST);
        ck_assert_int_eq(scp_get_kill_session_request(g_server, &sid), 0);
        ck_assert_int_eq(sid, sids[i]);
        scp_msg_in_reset(g_server);
    }
}
END_TEST

/******************************************************************************/
/* Bad values must still be carried to sesman, which rejects them */
START_TEST(test_kill_request__bad_sids_are_transported)
{
    static const int sids[] = { 0, -1, INT_MIN };
    unsigned int i;

    for (i = 0 ; i < sizeof(sids) / sizeof(sids[0]); ++i)
    {
        int sid = 12345;

        ck_assert_int_eq(scp_send_kill_session_request(g_client, sids[i]), 0);
        expect_message(g_server, E_SCP_KILL_SESSION_REQUEST);
        ck_assert_int_eq(scp_get_kill_session_request(g_server, &sid), 0);
        ck_assert_int_eq(sid, sids[i]);
        scp_msg_in_reset(g_server);
    }
}
END_TEST

/******************************************************************************/
START_TEST(test_kill_response__round_trip)
{
    static const enum scp_kill_session_status statuses[] =
    {
        E_SCP_KS_OK,
        E_SCP_KS_NOT_LOGGED_IN,
        E_SCP_KS_NO_SUCH_SESSION,
        E_SCP_KS_BAD_SID,
        E_SCP_KS_SIGNAL_FAILED
    };
    unsigned int i;

    for (i = 0 ; i < sizeof(statuses) / sizeof(statuses[0]); ++i)
    {
        /* Start with a value which is never sent */
        enum scp_kill_session_status status = (enum scp_kill_session_status)999;

        ck_assert_int_eq(scp_send_kill_session_response(g_server,
                         statuses[i]), 0);
        expect_message(g_client, E_SCP_KILL_SESSION_RESPONSE);
        ck_assert_int_eq(scp_get_kill_session_response(g_client, &status), 0);
        ck_assert_int_eq(status, statuses[i]);
        scp_msg_in_reset(g_client);
    }
}
END_TEST

/******************************************************************************/
/* A request with the wrong payload type must be rejected, and the
 * output value must not be touched */
START_TEST(test_kill_request__wrong_payload_rejected)
{
    int sid = 999;

    ck_assert_int_eq(libipm_msg_out_simple_send(
                         g_client, (int)E_SCP_KILL_SESSION_REQUEST,
                         "s", "1234"), 0);
    expect_message(g_server, E_SCP_KILL_SESSION_REQUEST);
    ck_assert_int_ne(scp_get_kill_session_request(g_server, &sid), 0);
    ck_assert_int_eq(sid, 999);
}
END_TEST

/******************************************************************************/
/* A request with no payload at all must be rejected */
START_TEST(test_kill_request__empty_payload_rejected)
{
    int sid = 999;

    ck_assert_int_eq(libipm_msg_out_simple_send(
                         g_client, (int)E_SCP_KILL_SESSION_REQUEST,
                         NULL), 0);
    expect_message(g_server, E_SCP_KILL_SESSION_REQUEST);
    ck_assert_int_ne(scp_get_kill_session_request(g_server, &sid), 0);
    ck_assert_int_eq(sid, 999);
}
END_TEST

/******************************************************************************/
/* The synchronous call sends the request and returns the status from
 * the response */
START_TEST(test_kill_sync__returns_status)
{
    enum scp_kill_session_status status = E_SCP_KS_OK;
    int sid = -1;

    /* Queue the server's answer first. The socket buffers it until the
     * client reads it, so a single thread can test the call */
    ck_assert_int_eq(scp_send_kill_session_response(
                         g_server, E_SCP_KS_NO_SUCH_SESSION), 0);

    ck_assert_int_eq(scp_sync_kill_session_request(g_client, 4321,
                     &status), 0);
    ck_assert_int_eq(status, E_SCP_KS_NO_SUCH_SESSION);

    /* The request should be waiting for the server */
    expect_message(g_server, E_SCP_KILL_SESSION_REQUEST);
    ck_assert_int_eq(scp_get_kill_session_request(g_server, &sid), 0);
    ck_assert_int_eq(sid, 4321);
}
END_TEST

/******************************************************************************/
START_TEST(test_kill_msgno_to_str)
{
    char buff[64];

    ck_assert_str_eq(scp_msgno_to_str(E_SCP_KILL_SESSION_REQUEST,
                                      buff, sizeof(buff)),
                     "SCP_KILL_SESSION_REQUEST");
    ck_assert_str_eq(scp_msgno_to_str(E_SCP_KILL_SESSION_RESPONSE,
                                      buff, sizeof(buff)),
                     "SCP_KILL_SESSION_RESPONSE");
}
END_TEST

/******************************************************************************/
/* Existing message numbers must not change, or old clients break */
START_TEST(test_kill_msgno__existing_numbers_unchanged)
{
    ck_assert_int_eq(E_SCP_SET_PEERNAME_REQUEST, 1);
    ck_assert_int_eq(E_SCP_CLOSE_CONNECTION_REQUEST, 14);
    ck_assert_int_eq(E_SCP_KILL_SESSION_REQUEST, 15);
    ck_assert_int_eq(E_SCP_KILL_SESSION_RESPONSE, 16);
}
END_TEST

/******************************************************************************/
START_TEST(test_kill_status_to_str)
{
    char buff[64];

    ck_assert_str_eq(scp_kill_session_status_to_str(E_SCP_KS_OK,
                     buff, sizeof(buff)), "OK");
    ck_assert_str_eq(scp_kill_session_status_to_str(E_SCP_KS_NO_SUCH_SESSION,
                     buff, sizeof(buff)), "No such session for this user");

    /* Unknown codes are shown as numbers */
    ck_assert_str_eq(scp_kill_session_status_to_str(
                         (enum scp_kill_session_status)77,
                         buff, sizeof(buff)),
                     "[kill session error code #77]");
}
END_TEST

/******************************************************************************/
Suite *
make_suite_test_scp_kill_session(void)
{
    Suite *s;
    TCase *tc;

    s = suite_create("SCP kill session");

    tc = tcase_create("messages");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_kill_request__round_trip);
    tcase_add_test(tc, test_kill_request__bad_sids_are_transported);
    tcase_add_test(tc, test_kill_response__round_trip);
    tcase_add_test(tc, test_kill_request__wrong_payload_rejected);
    tcase_add_test(tc, test_kill_request__empty_payload_rejected);
    tcase_add_test(tc, test_kill_sync__returns_status);
    suite_add_tcase(s, tc);

    tc = tcase_create("strings");
    tcase_add_test(tc, test_kill_msgno_to_str);
    tcase_add_test(tc, test_kill_msgno__existing_numbers_unchanged);
    tcase_add_test(tc, test_kill_status_to_str);
    suite_add_tcase(s, tc);

    return s;
}
