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
 * @file test_session_audit.c
 * @brief Tests for the session audit log
 *
 */

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "list.h"
#include "session_audit.h"

#include "test_sesman.h"

/* 2026-11-17T04:30:10Z */
#define T0 ((time_t)1794889810)

static char g_dir[64];
static char g_log[128];

/******************************************************************************/
static void
setup(void)
{
    strcpy(g_dir, "/tmp/test_session_audit_XXXXXX");
    ck_assert_ptr_nonnull(mkdtemp(g_dir));
    snprintf(g_log, sizeof(g_log), "%s/audit.log", g_dir);
}

/******************************************************************************/
static void
teardown(void)
{
    char path[160];

    /* Remove the files the tests can create, then the directory */
    unlink(g_log);
    snprintf(path, sizeof(path), "%s/target", g_dir);
    unlink(path);
    ck_assert_int_eq(rmdir(g_dir), 0);
}

/******************************************************************************/
static struct session_audit_record
make_record(enum session_audit_event e, int sid, const char *user)
{
    struct session_audit_record r;
    memset(&r, 0, sizeof(r));
    r.event = e;
    r.time = T0;
    r.sid = sid;
    r.user = user;
    return r;
}

/******************************************************************************/
/* Append raw text to the log, as if another program wrote it */
static void
append_raw(const char *text)
{
    FILE *fp = fopen(g_log, "a");
    ck_assert_ptr_nonnull(fp);
    fputs(text, fp);
    fclose(fp);
}

/******************************************************************************/
START_TEST(test_format__all_fields)
{
    char buff[SESSION_AUDIT_MAX_LINE];
    struct session_audit_record r = make_record(SA_CLIENT_CONNECT, 3124,
                                    "alice");
    r.ip = "192.168.0.20";
    r.display = "X11-10";
    r.client = "LAPTOP";
    r.actor = "boss";

    ck_assert_uint_gt(session_audit_format(&r, buff, sizeof(buff)), 0);
    ck_assert_str_eq(buff,
                     "time=2026-11-17T04:30:10Z event=CLIENT_CONNECT "
                     "sid=3124 user=alice ip=192.168.0.20 display=X11-10 "
                     "client=LAPTOP actor=boss\n");
}
END_TEST

/******************************************************************************/
START_TEST(test_format__missing_fields)
{
    char buff[SESSION_AUDIT_MAX_LINE];
    struct session_audit_record r = make_record(SA_IP_BLOCKED, 0, NULL);
    r.ip = "10.0.0.1";
    r.display = "";

    session_audit_format(&r, buff, sizeof(buff));
    ck_assert_str_eq(buff,
                     "time=2026-11-17T04:30:10Z event=IP_BLOCKED sid=- "
                     "user=- ip=10.0.0.1 display=- client=- actor=-\n");
}
END_TEST

/******************************************************************************/
/* A value can't start a new line or add a fake field */
START_TEST(test_format__injection_escaped)
{
    char buff[SESSION_AUDIT_MAX_LINE];
    struct session_audit_record r =
        make_record(SA_CLIENT_CONNECT, 1, "alice");
    r.client = "PC\ntime=x event=SESSION_KILL actor=root";

    session_audit_format(&r, buff, sizeof(buff));

    /* Exactly one newline, at the end */
    ck_assert_ptr_eq(strchr(buff, '\n'), buff + strlen(buff) - 1);
    ck_assert_ptr_nonnull(strstr(buff,
                                 "client=PC\\x0atime\\x3dx\\x20event\\x3d"
                                 "SESSION_KILL\\x20actor\\x3droot "));
    /* The real actor field is still the last one */
    ck_assert_ptr_nonnull(strstr(buff, " actor=-\n"));
}
END_TEST

/******************************************************************************/
START_TEST(test_format__special_chars)
{
    char buff[SESSION_AUDIT_MAX_LINE];
    struct session_audit_record r = make_record(SA_SESSION_START, 1,
                                    "a b\tc\\d\x7f" "e\x01");
    session_audit_format(&r, buff, sizeof(buff));
    ck_assert_ptr_nonnull(strstr(buff,
                                 " user=a\\x20b\\x09c\\x5cd\\x7fe\\x01 "));
}
END_TEST

/******************************************************************************/
/* UTF-8 text such as Korean names is kept as it is */
START_TEST(test_format__utf8_kept)
{
    char buff[SESSION_AUDIT_MAX_LINE];
    struct session_audit_record r = make_record(SA_SESSION_START, 1,
                                    "\xec\x9c\xa4\xeb\xaf\xbc\xec\x9e\xac");
    session_audit_format(&r, buff, sizeof(buff));
    ck_assert_ptr_nonnull(strstr(buff,
                                 " user=\xec\x9c\xa4\xeb\xaf\xbc\xec\x9e\xac "));
}
END_TEST

/******************************************************************************/
/* Very long values are cut short. The line still ends with a newline,
 * and an escape sequence is never split */
START_TEST(test_format__long_value_truncated)
{
    char buff[SESSION_AUDIT_MAX_LINE];
    char longname[3000];
    size_t len;
    struct session_audit_record r;

    memset(longname, ' ', sizeof(longname) - 1); /* Each becomes \x20 */
    longname[sizeof(longname) - 1] = '\0';
    r = make_record(SA_CLIENT_CONNECT, 1, "alice");
    r.client = longname;

    len = session_audit_format(&r, buff, sizeof(buff));
    ck_assert_uint_lt(len, sizeof(buff));
    ck_assert_uint_eq(strlen(buff), len);
    ck_assert_int_eq(buff[len - 1], '\n');
    /* The text before the newline ends with a whole "\x20" */
    ck_assert_int_eq(strncmp(buff + len - 5, "\\x20", 4), 0);
}
END_TEST

/******************************************************************************/
START_TEST(test_format__event_names)
{
    ck_assert_str_eq(session_audit_event_to_str(SA_SESSION_START),
                     "SESSION_START");
    ck_assert_str_eq(session_audit_event_to_str(SA_SESSION_RESTORED),
                     "SESSION_RESTORED");
    ck_assert_str_eq(session_audit_event_to_str(SA_SESSION_FINISH),
                     "SESSION_FINISH");
    ck_assert_str_eq(session_audit_event_to_str(SA_CLIENT_CONNECT),
                     "CLIENT_CONNECT");
    ck_assert_str_eq(session_audit_event_to_str(SA_CLIENT_DISCONNECT),
                     "CLIENT_DISCONNECT");
    ck_assert_str_eq(session_audit_event_to_str(SA_SESSION_KILL),
                     "SESSION_KILL");
    ck_assert_str_eq(session_audit_event_to_str(SA_IP_BLOCKED),
                     "IP_BLOCKED");
}
END_TEST

/******************************************************************************/
START_TEST(test_write__creates_private_file)
{
    struct stat st;
    struct session_audit_record r = make_record(SA_SESSION_START, 5, "alice");

    ck_assert_int_eq(session_audit_write(g_log, &r), 0);
    ck_assert_int_eq(stat(g_log, &st), 0);
    ck_assert_int_eq(st.st_mode & 0777, 0600);
}
END_TEST

/******************************************************************************/
START_TEST(test_write__appends)
{
    struct list *lines;
    struct session_audit_record r1 = make_record(SA_SESSION_START, 1, "a");
    struct session_audit_record r2 = make_record(SA_SESSION_FINISH, 1, "a");

    ck_assert_int_eq(session_audit_write(g_log, &r1), 0);
    ck_assert_int_eq(session_audit_write(g_log, &r2), 0);

    lines = session_audit_read_last(g_log, 10);
    ck_assert_ptr_nonnull(lines);
    ck_assert_int_eq(lines->count, 2);
    ck_assert_ptr_nonnull(strstr((char *)lines->items[0], "SESSION_START"));
    ck_assert_ptr_nonnull(strstr((char *)lines->items[1], "SESSION_FINISH"));
    list_delete(lines);
}
END_TEST

/******************************************************************************/
START_TEST(test_write__disabled)
{
    struct session_audit_record r = make_record(SA_SESSION_START, 1, "a");
    ck_assert_int_eq(session_audit_write("", &r), 0);
    ck_assert_int_eq(session_audit_write(NULL, &r), 0);
    ck_assert_int_ne(access(g_log, F_OK), 0);
}
END_TEST

/******************************************************************************/
/* A failure is reported, not fatal */
START_TEST(test_write__bad_directory)
{
    char path[160];
    struct session_audit_record r = make_record(SA_SESSION_START, 1, "a");
    snprintf(path, sizeof(path), "%s/no/such/dir/audit.log", g_dir);
    ck_assert_int_ne(session_audit_write(path, &r), 0);
}
END_TEST

/******************************************************************************/
/* The log can't be redirected to another file with a symlink */
START_TEST(test_write__symlink_refused)
{
    char target[160];
    struct stat st;
    struct session_audit_record r = make_record(SA_SESSION_START, 1, "a");

    snprintf(target, sizeof(target), "%s/target", g_dir);
    append_raw(""); /* Create nothing yet */
    unlink(g_log);
    ck_assert_int_eq(symlink(target, g_log), 0);

    ck_assert_int_ne(session_audit_write(g_log, &r), 0);
    ck_assert_int_ne(stat(target, &st), 0); /* target not created */
}
END_TEST

/******************************************************************************/
START_TEST(test_read__missing_file_is_empty)
{
    struct list *lines = session_audit_read_last(g_log, 20);
    ck_assert_ptr_nonnull(lines);
    ck_assert_int_eq(lines->count, 0);
    list_delete(lines);
}
END_TEST

/******************************************************************************/
START_TEST(test_read__last_n)
{
    struct list *lines;
    int i;

    for (i = 1 ; i <= 5 ; ++i)
    {
        struct session_audit_record r = make_record(SA_SESSION_START, i, "a");
        ck_assert_int_eq(session_audit_write(g_log, &r), 0);
    }

    /* Last 2, oldest first */
    lines = session_audit_read_last(g_log, 2);
    ck_assert_ptr_nonnull(lines);
    ck_assert_int_eq(lines->count, 2);
    ck_assert_ptr_nonnull(strstr((char *)lines->items[0], " sid=4 "));
    ck_assert_ptr_nonnull(strstr((char *)lines->items[1], " sid=5 "));
    list_delete(lines);

    /* Asking for more than there are gives them all */
    lines = session_audit_read_last(g_log, 100);
    ck_assert_ptr_nonnull(lines);
    ck_assert_int_eq(lines->count, 5);
    ck_assert_ptr_nonnull(strstr((char *)lines->items[0], " sid=1 "));
    list_delete(lines);
}
END_TEST

/******************************************************************************/
START_TEST(test_read__bad_count)
{
    ck_assert_ptr_null(session_audit_read_last(g_log, 0));
    ck_assert_ptr_null(session_audit_read_last(g_log,
                       SESSION_AUDIT_MAX_HISTORY + 1));
}
END_TEST

/******************************************************************************/
/* A big file is read from the end, and the cut-off first line is
 * not returned */
START_TEST(test_read__big_file)
{
    struct list *lines;
    int i;
    char filler[600];

    memset(filler, 'x', sizeof(filler) - 2);
    filler[sizeof(filler) - 2] = '\n';
    filler[sizeof(filler) - 1] = '\0';
    for (i = 0 ; i < 50 ; ++i)
    {
        append_raw(filler);
    }
    for (i = 1 ; i <= 3 ; ++i)
    {
        struct session_audit_record r = make_record(SA_SESSION_START, i, "a");
        ck_assert_int_eq(session_audit_write(g_log, &r), 0);
    }

    lines = session_audit_read_last(g_log, 3);
    ck_assert_ptr_nonnull(lines);
    ck_assert_int_eq(lines->count, 3);
    ck_assert_ptr_nonnull(strstr((char *)lines->items[0], " sid=1 "));
    ck_assert_ptr_nonnull(strstr((char *)lines->items[2], " sid=3 "));
    list_delete(lines);
}
END_TEST

/******************************************************************************/
/* A line still being written (no newline yet) is not returned */
START_TEST(test_read__incomplete_last_line)
{
    struct list *lines;
    struct session_audit_record r = make_record(SA_SESSION_START, 7, "a");

    ck_assert_int_eq(session_audit_write(g_log, &r), 0);
    append_raw("time=2026-11-17T04:30:11Z event=SESS");

    lines = session_audit_read_last(g_log, 10);
    ck_assert_ptr_nonnull(lines);
    ck_assert_int_eq(lines->count, 1);
    ck_assert_ptr_nonnull(strstr((char *)lines->items[0], " sid=7 "));
    list_delete(lines);
}
END_TEST

/******************************************************************************/
Suite *
make_suite_test_session_audit(void)
{
    Suite *s;
    TCase *tc;

    s = suite_create("SessionAudit");

    tc = tcase_create("format");
    tcase_add_test(tc, test_format__all_fields);
    tcase_add_test(tc, test_format__missing_fields);
    tcase_add_test(tc, test_format__injection_escaped);
    tcase_add_test(tc, test_format__special_chars);
    tcase_add_test(tc, test_format__utf8_kept);
    tcase_add_test(tc, test_format__long_value_truncated);
    tcase_add_test(tc, test_format__event_names);
    suite_add_tcase(s, tc);

    tc = tcase_create("file");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_write__creates_private_file);
    tcase_add_test(tc, test_write__appends);
    tcase_add_test(tc, test_write__disabled);
    tcase_add_test(tc, test_write__bad_directory);
    tcase_add_test(tc, test_write__symlink_refused);
    tcase_add_test(tc, test_read__missing_file_is_empty);
    tcase_add_test(tc, test_read__last_n);
    tcase_add_test(tc, test_read__bad_count);
    tcase_add_test(tc, test_read__big_file);
    tcase_add_test(tc, test_read__incomplete_last_line);
    suite_add_tcase(s, tc);

    return s;
}
