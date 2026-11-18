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
 * @file login_ban.c
 * @brief Blocks IP addresses after repeated login failures
 *
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>  /* AF_INET, AF_INET6 (needed on FreeBSD) */
#include <netinet/in.h>
#include <arpa/inet.h>

#include "login_ban.h"
#include "os_calls.h"
#include "string_calls.h"

struct login_ban_entry
{
    char ip[LOGIN_BAN_IP_LEN];
    unsigned int failures;   ///< Failures in the current window
    time_t first_failure;    ///< Start of the current window
    time_t last_failure;     ///< Used to find the oldest entry
    time_t banned_until;     ///< 0 if not blocked
};

struct login_ban
{
    unsigned int max_entries;
    unsigned int count;
    struct login_ban_entry *entries;
};

/*****************************************************************************/
struct login_ban *
login_ban_create(unsigned int max_entries)
{
    struct login_ban *self = g_new0(struct login_ban, 1);

    if (self != NULL)
    {
        if (max_entries == 0)
        {
            max_entries = LOGIN_BAN_DEFAULT_MAX_ENTRIES;
        }
        self->entries = g_new0(struct login_ban_entry, max_entries);
        if (self->entries == NULL)
        {
            g_free(self);
            self = NULL;
        }
        else
        {
            self->max_entries = max_entries;
        }
    }

    return self;
}

/*****************************************************************************/
void
login_ban_delete(struct login_ban *self)
{
    if (self != NULL)
    {
        g_free(self->entries);
        g_free(self);
    }
}

/*****************************************************************************/
int
login_ban_normalise_ip(const char *ip, char *buff, size_t bufflen)
{
    struct in_addr a4;
    struct in6_addr a6;

    if (ip == NULL || buff == NULL || bufflen == 0)
    {
        return 1;
    }

    if (inet_pton(AF_INET, ip, &a4) == 1)
    {
        return (inet_ntop(AF_INET, &a4, buff, bufflen) == NULL);
    }

    if (inet_pton(AF_INET6, ip, &a6) == 1)
    {
        if (IN6_IS_ADDR_V4MAPPED(&a6))
        {
            /* The IPv4 address is in the last 4 bytes */
            memcpy(&a4, &a6.s6_addr[12], sizeof(a4));
            return (inet_ntop(AF_INET, &a4, buff, bufflen) == NULL);
        }
        return (inet_ntop(AF_INET6, &a6, buff, bufflen) == NULL);
    }

    return 1;
}

/*****************************************************************************/
/* Is this entry finished with, so it can be reused? */
static int
entry_is_expired(const struct login_ban_entry *e,
                 const struct login_ban_config *cfg, time_t now)
{
    if (e->banned_until != 0)
    {
        return (now >= e->banned_until);
    }
    return (e->failures == 0 || now - e->first_failure >= (time_t)cfg->window);
}

/*****************************************************************************/
static void
remove_entry(struct login_ban *self, unsigned int index)
{
    /* Move the last entry into the gap. Order doesn't matter */
    --self->count;
    if (index != self->count)
    {
        self->entries[index] = self->entries[self->count];
    }
    g_memset(&self->entries[self->count], 0, sizeof(self->entries[0]));
}

/*****************************************************************************/
static struct login_ban_entry *
find_entry(struct login_ban *self, const char *norm_ip, unsigned int *index)
{
    unsigned int i;
    for (i = 0 ; i < self->count ; ++i)
    {
        if (g_strcmp(self->entries[i].ip, norm_ip) == 0)
        {
            if (index != NULL)
            {
                *index = i;
            }
            return &self->entries[i];
        }
    }
    return NULL;
}

/*****************************************************************************/
/* Makes room for a new entry when the table is full. Expired entries go
 * first. If there are none, the entry with the oldest failure goes */
static void
make_room(struct login_ban *self, const struct login_ban_config *cfg,
          time_t now)
{
    unsigned int i = 0;

    while (i < self->count)
    {
        if (entry_is_expired(&self->entries[i], cfg, now))
        {
            remove_entry(self, i); // Don't advance i - a new entry is here
        }
        else
        {
            ++i;
        }
    }

    if (self->count >= self->max_entries)
    {
        unsigned int oldest = 0;
        for (i = 1 ; i < self->count ; ++i)
        {
            if (self->entries[i].last_failure <
                    self->entries[oldest].last_failure)
            {
                oldest = i;
            }
        }
        remove_entry(self, oldest);
    }
}

/*****************************************************************************/
int
login_ban_is_blocked(struct login_ban *self,
                     const struct login_ban_config *cfg,
                     const char *ip, time_t now,
                     unsigned int *remaining)
{
    char norm_ip[LOGIN_BAN_IP_LEN];
    struct login_ban_entry *e;

    if (remaining != NULL)
    {
        *remaining = 0;
    }

    if (self == NULL || cfg == NULL || cfg->max_failures == 0 ||
            login_ban_normalise_ip(ip, norm_ip, sizeof(norm_ip)) != 0)
    {
        return 0;
    }

    e = find_entry(self, norm_ip, NULL);
    if (e == NULL || e->banned_until == 0 || now >= e->banned_until)
    {
        return 0;
    }

    if (remaining != NULL)
    {
        *remaining = (unsigned int)(e->banned_until - now);
    }
    return 1;
}

/*****************************************************************************/
enum login_ban_result
login_ban_record_failure(struct login_ban *self,
                         const struct login_ban_config *cfg,
                         const char *ip, time_t now)
{
    char norm_ip[LOGIN_BAN_IP_LEN];
    struct login_ban_entry *e;

    if (self == NULL || cfg == NULL || cfg->max_failures == 0 ||
            login_ban_normalise_ip(ip, norm_ip, sizeof(norm_ip)) != 0)
    {
        return LOGIN_BAN_NOT_BLOCKED;
    }

    e = find_entry(self, norm_ip, NULL);
    if (e != NULL)
    {
        if (e->banned_until != 0 && now < e->banned_until)
        {
            /* Already blocked. Don't extend the block, so that a
             * client which keeps trying is not blocked forever */
            return LOGIN_BAN_ALREADY_BLOCKED;
        }
        if (entry_is_expired(e, cfg, now))
        {
            /* Start a new window for this address */
            e->failures = 0;
            e->banned_until = 0;
        }
    }
    else
    {
        if (self->count >= self->max_entries)
        {
            make_room(self, cfg, now);
        }
        e = &self->entries[self->count++];
        g_memset(e, 0, sizeof(*e));
        g_strncpy(e->ip, norm_ip, sizeof(e->ip) - 1);
    }

    if (e->failures == 0)
    {
        e->first_failure = now;
    }
    ++e->failures;
    e->last_failure = now;

    if (e->failures >= cfg->max_failures && cfg->ban_time > 0)
    {
        e->banned_until = now + (time_t)cfg->ban_time;
        return LOGIN_BAN_NEWLY_BLOCKED;
    }

    return LOGIN_BAN_NOT_BLOCKED;
}

/*****************************************************************************/
void
login_ban_record_success(struct login_ban *self, const char *ip)
{
    char norm_ip[LOGIN_BAN_IP_LEN];
    unsigned int index;

    if (self != NULL &&
            login_ban_normalise_ip(ip, norm_ip, sizeof(norm_ip)) == 0 &&
            find_entry(self, norm_ip, &index) != NULL)
    {
        remove_entry(self, index);
    }
}

/*****************************************************************************/
unsigned int
login_ban_get_count(const struct login_ban *self)
{
    return (self == NULL) ? 0 : self->count;
}
