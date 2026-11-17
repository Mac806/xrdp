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
 * @file session_audit.c
 * @brief Session audit log
 *
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "list.h"
#include "log.h"
#include "os_calls.h"
#include "session_audit.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

/* Builds a line in a fixed buffer. Room is always kept for the final
 * newline and NUL */
struct line_buff
{
    char *p;
    size_t used;
    size_t limit; // Usable length, not counting the newline and NUL
};

/*****************************************************************************/
const char *
session_audit_event_to_str(enum session_audit_event event)
{
    switch (event)
    {
        case SA_SESSION_START:
            return "SESSION_START";
        case SA_SESSION_RESTORED:
            return "SESSION_RESTORED";
        case SA_SESSION_FINISH:
            return "SESSION_FINISH";
        case SA_CLIENT_CONNECT:
            return "CLIENT_CONNECT";
        case SA_CLIENT_DISCONNECT:
            return "CLIENT_DISCONNECT";
        case SA_SESSION_KILL:
            return "SESSION_KILL";
        case SA_IP_BLOCKED:
            return "IP_BLOCKED";
    }
    return "UNKNOWN";
}

/*****************************************************************************/
/* Adds raw text, which must not need escaping. Text which doesn't fit
 * is dropped */
static void
add_raw(struct line_buff *lb, const char *s)
{
    size_t len = strlen(s);
    if (lb->used + len <= lb->limit)
    {
        memcpy(lb->p + lb->used, s, len);
        lb->used += len;
    }
}

/*****************************************************************************/
/* Adds a value. Bytes which could break the format are written as \xHH.
 * UTF-8 text (bytes >= 0x80) is kept, so non-English names are readable.
 * An escape sequence is never split if the buffer fills up */
static void
add_value(struct line_buff *lb, const char *s)
{
    static const char hex[] = "0123456789abcdef";

    if (s == NULL || *s == '\0')
    {
        add_raw(lb, "-");
        return;
    }

    for (; *s != '\0'; ++s)
    {
        unsigned char c = (unsigned char) * s;
        if (c <= 0x20 || c == 0x7f || c == '\\' || c == '=')
        {
            if (lb->used + 4 > lb->limit)
            {
                break;
            }
            lb->p[lb->used++] = '\\';
            lb->p[lb->used++] = 'x';
            lb->p[lb->used++] = hex[c >> 4];
            lb->p[lb->used++] = hex[c & 0xf];
        }
        else
        {
            if (lb->used + 1 > lb->limit)
            {
                break;
            }
            lb->p[lb->used++] = (char)c;
        }
    }
}

/*****************************************************************************/
static void
add_field(struct line_buff *lb, const char *key, const char *value)
{
    add_raw(lb, " ");
    add_raw(lb, key);
    add_raw(lb, "=");
    add_value(lb, value);
}

/*****************************************************************************/
size_t
session_audit_format(const struct session_audit_record *rec,
                     char *buff, size_t bufflen)
{
    struct line_buff lb;
    char text[64];
    struct tm tm;

    if (buff == NULL || bufflen < 2)
    {
        return 0;
    }

    lb.p = buff;
    lb.used = 0;
    lb.limit = bufflen - 2;

    /* Always UTC, so lines from different servers can be compared */
    if (gmtime_r(&rec->time, &tm) != NULL &&
            strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &tm) > 0)
    {
        add_raw(&lb, "time=");
        add_raw(&lb, text);
    }
    else
    {
        add_raw(&lb, "time=-");
    }

    add_raw(&lb, " event=");
    add_raw(&lb, session_audit_event_to_str(rec->event));

    if (rec->sid > 0)
    {
        snprintf(text, sizeof(text), "%d", rec->sid);
    }
    else
    {
        text[0] = '\0';
    }
    add_field(&lb, "sid", text);
    add_field(&lb, "user", rec->user);
    add_field(&lb, "ip", rec->ip);
    add_field(&lb, "display", rec->display);
    add_field(&lb, "client", rec->client);
    add_field(&lb, "actor", rec->actor);

    buff[lb.used++] = '\n';
    buff[lb.used] = '\0';
    return lb.used;
}

/*****************************************************************************/
int
session_audit_write(const char *path,
                    const struct session_audit_record *rec)
{
    char line[SESSION_AUDIT_MAX_LINE];
    size_t len;
    int fd;
    int rv = 0;

    if (path == NULL || path[0] == '\0' || rec == NULL)
    {
        return 0;
    }

    len = session_audit_format(rec, line, sizeof(line));

    /* O_NOFOLLOW stops the log being redirected through a symlink */
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW,
              S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        LOG(LOG_LEVEL_ERROR, "Can't open audit log %s [%s]",
            path, g_get_strerror());
        return 1;
    }

    /* A single write() in append mode, so lines from different writers
     * can't be mixed up */
    if (write(fd, line, len) != (ssize_t)len)
    {
        LOG(LOG_LEVEL_ERROR, "Can't write to audit log %s [%s]",
            path, g_get_strerror());
        rv = 1;
    }

    close(fd);
    return rv;
}

/*****************************************************************************/
struct list *
session_audit_read_last(const char *path, unsigned int count)
{
    struct list *result = NULL;
    struct stat st;
    char *data = NULL;
    size_t want;
    size_t got = 0;
    off_t start;
    int fd = -1;

    if (path == NULL || path[0] == '\0' ||
            count == 0 || count > SESSION_AUDIT_MAX_HISTORY)
    {
        return NULL;
    }

    if ((result = list_create()) == NULL)
    {
        return NULL;
    }
    result->auto_free = 1;

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
    {
        if (errno == ENOENT)
        {
            return result; /* No log yet - no records */
        }
        LOG(LOG_LEVEL_ERROR, "Can't open audit log %s [%s]",
            path, g_get_strerror());
        list_delete(result);
        return NULL;
    }

    if (fstat(fd, &st) != 0)
    {
        LOG(LOG_LEVEL_ERROR, "Can't stat audit log %s [%s]",
            path, g_get_strerror());
        goto fail;
    }

    /* Every line we write fits in SESSION_AUDIT_MAX_LINE, so the last
     * 'count' lines are within this many bytes of the end. We only read
     * that much, however big the file is */
    want = (size_t)count * SESSION_AUDIT_MAX_LINE;
    start = 0;
    if (st.st_size > (off_t)want)
    {
        start = st.st_size - (off_t)want;
    }
    want = (size_t)(st.st_size - start);

    if ((data = (char *)g_malloc(want + 1, 0)) == NULL)
    {
        LOG(LOG_LEVEL_ERROR, "Out of memory reading audit log");
        goto fail;
    }

    while (got < want)
    {
        ssize_t n = pread(fd, data + got, want - got, start + (off_t)got);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            LOG(LOG_LEVEL_ERROR, "Can't read audit log %s [%s]",
                path, g_get_strerror());
            goto fail;
        }
        if (n == 0)
        {
            break; /* File got shorter - use what we have */
        }
        got += (size_t)n;
    }
    data[got] = '\0';
    close(fd);
    fd = -1;

    {
        char *p = data;
        char *end = data + got;
        unsigned int lines = 0;
        unsigned int skip;

        /* If we started part-way through the file, drop the first
         * (probably partial) line */
        if (start > 0)
        {
            char *nl = memchr(p, '\n', got);
            p = (nl == NULL) ? end : nl + 1;
        }

        /* Count complete lines, then skip the ones we don't need */
        {
            char *q;
            for (q = p; q < end; ++q)
            {
                if (*q == '\n')
                {
                    ++lines;
                }
            }
        }
        skip = (lines > count) ? lines - count : 0;

        while (p < end)
        {
            char *nl = memchr(p, '\n', (size_t)(end - p));
            if (nl == NULL)
            {
                break; /* Incomplete last line - being written now */
            }
            *nl = '\0';
            if (skip > 0)
            {
                --skip;
            }
            else if (!list_add_strdup(result, p))
            {
                LOG(LOG_LEVEL_ERROR, "Out of memory reading audit log");
                goto fail;
            }
            p = nl + 1;
        }
    }

    g_free(data);
    return result;

fail:
    if (fd >= 0)
    {
        close(fd);
    }
    g_free(data);
    list_delete(result);
    return NULL;
}
