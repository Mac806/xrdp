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
 * @file session_audit.h
 * @brief Session audit log
 *
 * sesman writes one line to the audit log for each important session
 * event, in a fixed key=value format which is easy to search:-
 *
 * time=2026-11-17T04:30:10Z event=SESSION_START sid=3124 user=alice
 *     ip=192.168.0.20 display=X11-10 client=- actor=-
 *
 * (all on one line). Values never contain spaces, '=' or control
 * characters, so a value can't be used to fake another field or line.
 *
 * The module does not read the clock or the configuration. These are
 * passed in by the caller, so the module can be tested on its own.
 *
 */

#ifndef SESSION_AUDIT_H
#define SESSION_AUDIT_H

#include <stddef.h>
#include <time.h>

struct list;

/** Longest line written to the log, including the newline */
#define SESSION_AUDIT_MAX_LINE 1024

/** Most lines which can be read back with session_audit_read_last() */
#define SESSION_AUDIT_MAX_HISTORY 1000

enum session_audit_event
{
    SA_SESSION_START,     ///< A new session has started
    SA_SESSION_RESTORED,  ///< An existing session was found after a restart
    SA_SESSION_FINISH,    ///< A session has ended
    SA_CLIENT_CONNECT,    ///< An RDP client connected to a session
    SA_CLIENT_DISCONNECT, ///< An RDP client disconnected from a session
    SA_SESSION_KILL,      ///< A session was killed with sesadmin
    SA_IP_BLOCKED         ///< An IP address was blocked after failed logins
};

/**
 * One audit record. String fields can be NULL or "", which are both
 * written as "-"
 */
struct session_audit_record
{
    enum session_audit_event event;
    time_t time;
    int sid;              ///< Session ID. <= 0 is written as "-"
    const char *user;     ///< Owner of the session
    const char *ip;       ///< Client IP address
    const char *display;  ///< Session display (e.g. "X11-10")
    const char *client;   ///< RDP client name
    const char *actor;    ///< Who caused the event (e.g. an admin)
};

/**
 * Get the name of an event, as it appears in the log
 *
 * @param event Event
 * @return Name of the event
 */
const char *
session_audit_event_to_str(enum session_audit_event event);

/**
 * Format a record as a single line, ending in a newline
 *
 * @param rec Record to format
 * @param[out] buff Buffer for the line
 * @param bufflen Length of buff. SESSION_AUDIT_MAX_LINE is enough.
 * @return Length of the line (without the NUL). If the line doesn't fit,
 *         values are cut short so that the newline is always present.
 */
size_t
session_audit_format(const struct session_audit_record *rec,
                     char *buff, size_t bufflen);

/**
 * Append a record to the audit log
 *
 * @param path Audit log file. If NULL or "", nothing is written.
 * @param rec Record to write
 * @return 0 for success (or nothing to do), != 0 for an error. Errors
 *         are logged. An error never stops sesman.
 *
 * The file is created if needed, with permissions 0600. It is opened
 * for each record, so log rotation works without telling sesman. The
 * line is written with a single write() in append mode.
 */
int
session_audit_write(const char *path,
                    const struct session_audit_record *rec);

/**
 * Read the last lines of the audit log
 *
 * @param path Audit log file
 * @param count Number of lines wanted (1 - SESSION_AUDIT_MAX_HISTORY)
 * @return List of lines (char *, without the newline), oldest first.
 *         If the file doesn't exist, an empty list is returned.
 *         NULL is returned for other errors, which are logged.
 *         The caller must call list_delete() on the result.
 */
struct list *
session_audit_read_last(const char *path, unsigned int count);

#endif /* SESSION_AUDIT_H */
