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
 * @file login_ban.h
 * @brief Blocks IP addresses after repeated login failures
 *
 * sesman keeps a table of client IP addresses which have recently failed
 * to log in. When an address fails too often within a time window, new
 * login attempts from it are refused for a while, before any sesexec
 * process is started to check a password.
 *
 * The module does not read the clock or the configuration itself. The
 * caller passes in the current time and the settings on each call, so
 * that the module can be tested with a fake clock, and so that changes
 * made by reloading sesman.ini take effect straight away.
 *
 */

#ifndef LOGIN_BAN_H
#define LOGIN_BAN_H

#include <stddef.h>
#include <time.h>

/** Default size of the table */
#define LOGIN_BAN_DEFAULT_MAX_ENTRIES 4096

/** Big enough for any normalised IPv4 or IPv6 address, with a NUL */
#define LOGIN_BAN_IP_LEN 46

/**
 * Settings for the ban table, from the [Security] section of sesman.ini
 */
struct login_ban_config
{
    /** Failures needed to block an address. 0 disables the feature */
    unsigned int max_failures;
    /** Seconds over which failures are counted */
    unsigned int window;
    /** Seconds an address stays blocked */
    unsigned int ban_time;
};

struct login_ban;

/**
 * Result of login_ban_record_failure()
 */
enum login_ban_result
{
    LOGIN_BAN_NOT_BLOCKED = 0,  ///< The address is not blocked
    LOGIN_BAN_NEWLY_BLOCKED,    ///< This failure has just blocked the address
    LOGIN_BAN_ALREADY_BLOCKED   ///< The address was already blocked
};

/**
 * Create a ban table
 *
 * @param max_entries Maximum number of addresses to track. If 0, the
 *                    default size is used.
 * @return New table, or NULL if memory is not available
 */
struct login_ban *
login_ban_create(unsigned int max_entries);

/**
 * Free a ban table
 *
 * @param self Table to free. May be NULL
 */
void
login_ban_delete(struct login_ban *self);

/**
 * Convert an IP address string to a single standard form
 *
 * IPv4 addresses mapped into IPv6 (e.g. "::ffff:10.0.0.1") are converted
 * to plain IPv4, so that the same client always gives the same key.
 *
 * @param ip Address to convert
 * @param[out] buff Buffer for the result
 * @param bufflen Length of buff. LOGIN_BAN_IP_LEN is always enough
 * @return 0 for success, != 0 if ip is not a valid IPv4 or IPv6 address
 */
int
login_ban_normalise_ip(const char *ip, char *buff, size_t bufflen);

/**
 * Is an IP address currently blocked?
 *
 * @param self Table
 * @param cfg Current settings
 * @param ip Client IP address
 * @param now Current time
 * @param[out] remaining Seconds left on the block. May be NULL
 * @return != 0 if the address is blocked
 */
int
login_ban_is_blocked(struct login_ban *self,
                     const struct login_ban_config *cfg,
                     const char *ip, time_t now,
                     unsigned int *remaining);

/**
 * Record a failed login from an IP address
 *
 * @param self Table
 * @param cfg Current settings
 * @param ip Client IP address. Invalid or empty addresses are ignored
 * @param now Current time
 * @return A value from enum login_ban_result. Any value other than
 *         LOGIN_BAN_NOT_BLOCKED means the address is blocked.
 *
 * LOGIN_BAN_NEWLY_BLOCKED is returned only once for each block, so that
 * the caller can log the block once. More failures while the address is
 * blocked (e.g. from a second connection which was already open) give
 * LOGIN_BAN_ALREADY_BLOCKED.
 */
enum login_ban_result
login_ban_record_failure(struct login_ban *self,
                         const struct login_ban_config *cfg,
                         const char *ip, time_t now);

/**
 * Record a successful login from an IP address
 *
 * This clears the failure count for the address.
 *
 * @param self Table
 * @param ip Client IP address
 */
void
login_ban_record_success(struct login_ban *self, const char *ip);

/**
 * Number of addresses currently tracked (for tests and logging)
 *
 * @param self Table
 * @return Count
 */
unsigned int
login_ban_get_count(const struct login_ban *self);

#endif /* LOGIN_BAN_H */
