/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2023
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
 * @file login_info.h
 * @brief Declare functionality associated with user logins for sesexec
 * @author Matt Burt
 *
 */

#ifndef LOGIN_INFO_H
#define LOGIN_INFO_H

#include <sys/types.h>

struct trans;

/**
 * Information associated with the logged-in user
 */
struct login_info
{
    uid_t uid;
    char *username;
    char  *ip_addr;
    struct auth_info *auth_info;
};

/**
 * Called each time a password check fails during a system login
 *
 * @param cb_data Data passed to login_info_sys_login_user()
 * @return != 0 if the client's IP address is now blocked, and no
 *         more attempts should be allowed
 */
typedef int (*login_failed_callback)(void *cb_data);

/**
 * @brief Attempt a system login using username/password
 * @param scp_trans SCP transport for talking to the client
 * @param username Username from xrdp
 * @param password Password from xrdp
 * @param ip_addr IP address for xrdp client
 * @param failed_cb Called after each failed password check. May be NULL
 * @param cb_data Passed to failed_cb
 *
 * @result Allocated login_info struct for a successful login
 *
 * This is a wrapper around the dialogue between sesexec and the SCP process
 * which is required to start a session.
 *
 * While this call is in operation, only the scp_trans transport will
 * be checked for messages. Incoming messages on other transports will be
 * ignored. The dialog can also be terminated by a SIGTERM if the SCP
 * transport is configured to allow this.
 *
 * The username in the returned structure may differ from the passed-in
 * username if multiple names map to the same UID. This can happen with
 * federated naming services (e.g. AD, LDAP)
 */
struct login_info *
login_info_sys_login_user(struct trans *scp_trans,
                          const char *username,
                          const char *password,
                          const char *ip_addr,
                          login_failed_callback failed_cb,
                          void *cb_data);

/**
 * @brief Create a login_info structure using UDS credentials
 *
 * This should be a formality, as by the time sesexec tries this, sesman
 * should already have done it.
 *
 * Errors are logged.
 *
 * @param scp_trans SCP transport for talking to the client
 *
 * @result Allocated login_info struct for a successful login
 */
struct login_info *
login_info_uds_login_user(struct trans *scp_trans);

/**
 * Free a struct login_info
 */
void
login_info_free(struct login_info *self);

#endif // LOGIN_INFO_H
