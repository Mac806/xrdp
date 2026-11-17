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
 * @file test_scp_audit_history.c
 * @brief Tests for the SCP audit history messages
 *
 */

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#include "libipm.h"
#include "list.h"
#include "os_calls.h"
#include "scp.h"
#include "scp_sync.h"
#include "trans.h"

#include "test_libipm.h"

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
static void
expect_message(struct trans *t, enum scp_msg_code expected)
{
    ck_assert_int_eq(scp_msg_in_wait_available(t), 0);
    ck_assert_int_eq(scp_msg_in_get_msgno(t), expected);
}

/******************************************************************************/
START_TEST(test_history_request__round_trip)
{
    int count = -1;

    ck_assert_int_eq(scp_send_audit_history_request(g_client, 20), 0);
    expect_message(g_server, E_SCP_AUDIT_HISTORY_REQUEST);
    ck_assert_int_eq(scp_get_audit_history_request(g_server, &count), 0);
    ck_assert_int_eq(count, 20);
}
END_TEST

/******************************************************************************/
START_TEST(test_history_response__record)
{
    enum scp_audit_history_status status = E_SCP_AH_READ_ERROR;
    const char *line = NULL;
    const char *sent = "time=2026-11-17T04:30:10Z event=SESSION_START sid=1";

    ck_assert_int_eq(scp_send_audit_history_response(g_server,
                     E_SCP_AH_RECORD, sent), 0);
    expect_message(g_client, E_SCP_AUDIT_HISTORY_RESPONSE);
    ck_assert_int_eq(scp_get_audit_history_response(g_client, &status,
                     &line), 0);
    ck_assert_int_eq(status, E_SCP_AH_RECORD);
    ck_assert_str_eq(line, sent);
}
END_TEST

/******************************************************************************/
/* The line is only sent with E_SCP_AH_RECORD */
START_TEST(test_history_response__no_line_for_other_status)
{
    enum scp_audit_history_status status = E_SCP_AH_RECORD;
    const char *line = NULL;

    ck_assert_int_eq(scp_send_audit_history_response(g_server,
                     E_SCP_AH_NOT_ADMIN, "secret"), 0);
    expect_message(g_client, E_SCP_AUDIT_HISTORY_RESPONSE);
    ck_assert_int_eq(scp_get_audit_history_response(g_client, &status,
                     &line), 0);
    ck_assert_int_eq(status, E_SCP_AH_NOT_ADMIN);
    ck_assert_str_eq(line, "");
}
END_TEST

/******************************************************************************/
/* A response with the wrong payload is rejected */
START_TEST(test_history_response__wrong_payload_rejected)
{
    enum scp_audit_history_status status = E_SCP_AH_READ_ERROR;
    const char *line = NULL;

    ck_assert_int_eq(libipm_msg_out_simple_send(
                         g_server, (int)E_SCP_AUDIT_HISTORY_RESPONSE,
                         "i", 0), 0);
    expect_message(g_client, E_SCP_AUDIT_HISTORY_RESPONSE);
    ck_assert_int_ne(scp_get_audit_history_response(g_client, &status,
                     &line), 0);
    ck_assert_ptr_null(line);
}
END_TEST

/******************************************************************************/
/* The synchronous call collects all the lines up to the end marker */
START_TEST(test_history_sync__collects_lines)
{
    enum scp_audit_history_status status = E_SCP_AH_READ_ERROR;
    struct list *lines;
    int count = -1;

    /* Queue sesman's answers first. The socket buffers them */
    ck_assert_int_eq(scp_send_audit_history_response(
                         g_server, E_SCP_AH_RECORD, "line one"), 0);
    ck_assert_int_eq(scp_send_audit_history_response(
                         g_server, E_SCP_AH_RECORD, "line two"), 0);
    ck_assert_int_eq(scp_send_audit_history_response(
                         g_server, E_SCP_AH_END_OF_LIST, NULL), 0);

    lines = scp_sync_audit_history_request(g_client, 2, &status);
    ck_assert_ptr_nonnull(lines);
    ck_assert_int_eq(status, E_SCP_AH_END_OF_LIST);
    ck_assert_int_eq(lines->count, 2);
    ck_assert_str_eq((const char *)lines->items[0], "line one");
    ck_assert_str_eq((const char *)lines->items[1], "line two");
    list_delete(lines);

    /* The request reached the server */
    expect_message(g_server, E_SCP_AUDIT_HISTORY_REQUEST);
    ck_assert_int_eq(scp_get_audit_history_request(g_server, &count), 0);
    ck_assert_int_eq(count, 2);
}
END_TEST

/******************************************************************************/
START_TEST(test_history_sync__error_status)
{
    enum scp_audit_history_status status = E_SCP_AH_RECORD;
    struct list *lines;

    ck_assert_int_eq(scp_send_audit_history_response(
                         g_server, E_SCP_AH_DISABLED, NULL), 0);

    lines = scp_sync_audit_history_request(g_client, 5, &status);
    ck_assert_ptr_nonnull(lines);
    ck_assert_int_eq(status, E_SCP_AH_DISABLED);
    ck_assert_int_eq(lines->count, 0);
    list_delete(lines);
}
END_TEST

/******************************************************************************/
START_TEST(test_history_msgno)
{
    char buff[64];

    /* New messages come after the kill session messages */
    ck_assert_int_eq(E_SCP_AUDIT_HISTORY_REQUEST, 17);
    ck_assert_int_eq(E_SCP_AUDIT_HISTORY_RESPONSE, 18);
    ck_assert_str_eq(scp_msgno_to_str(E_SCP_AUDIT_HISTORY_REQUEST,
                                      buff, sizeof(buff)),
                     "SCP_AUDIT_HISTORY_REQUEST");
    ck_assert_str_eq(scp_msgno_to_str(E_SCP_AUDIT_HISTORY_RESPONSE,
                                      buff, sizeof(buff)),
                     "SCP_AUDIT_HISTORY_RESPONSE");
}
END_TEST

/******************************************************************************/
START_TEST(test_history_status_to_str)
{
    char buff[64];

    ck_assert_str_eq(scp_audit_history_status_to_str(E_SCP_AH_NOT_ADMIN,
                     buff, sizeof(buff)),
                     "Only administrators can read the audit log");
    ck_assert_str_eq(scp_audit_history_status_to_str(
                         (enum scp_audit_history_status)77,
                         buff, sizeof(buff)),
                     "[audit history error code #77]");
}
END_TEST

/******************************************************************************/
Suite *
make_suite_test_scp_audit_history(void)
{
    Suite *s;
    TCase *tc;

    s = suite_create("SCP audit history");

    tc = tcase_create("messages");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_history_request__round_trip);
    tcase_add_test(tc, test_history_response__record);
    tcase_add_test(tc, test_history_response__no_line_for_other_status);
    tcase_add_test(tc, test_history_response__wrong_payload_rejected);
    tcase_add_test(tc, test_history_sync__collects_lines);
    tcase_add_test(tc, test_history_sync__error_status);
    suite_add_tcase(s, tc);

    tc = tcase_create("strings");
    tcase_add_test(tc, test_history_msgno);
    tcase_add_test(tc, test_history_status_to_str);
    suite_add_tcase(s, tc);

    return s;
}
