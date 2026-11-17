/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2013
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
 * @file sesman.h
 * @brief Main include file
 * @author Jay Sorg
 *
 */

#ifndef SESMAN_H
#define SESMAN_H

struct config_sesman;
struct trans;
struct login_ban;
struct login_ban_config;
struct session_item;

/* Globals */
extern struct config_sesman *g_cfg;
extern tintptr g_term_event;
extern struct login_ban *g_login_ban;

/**
 * Get the IP blocking settings from the current configuration
 *
 * @param[out] cfg Settings
 *
 * The settings are read from g_cfg each time, so that a configuration
 * reload takes effect straight away.
 */
void
sesman_get_login_ban_config(struct login_ban_config *cfg);

/**
 * Write a session event to the audit log (if enabled)
 *
 * @param event Event (an enum session_audit_event)
 * @param si Session
 * @param ip IP address to record (may be NULL)
 * @param client Client name to record (may be NULL)
 * @param actor User who caused the event (may be NULL)
 */
void
sesman_audit_session(int event, const struct session_item *si,
                     const char *ip, const char *client, const char *actor);

/**
 * Write a blocked IP address to the audit log (if enabled)
 *
 * @param ip Blocked IP address
 * @param username User name used in the last failed login
 */
void
sesman_audit_ip_blocked(const char *ip, const char *username);

/*
 * Remove the listening transport
 *
 * Needed if reloading the config and the listener has changed
 */
void
sesman_delete_listening_transport(void);

/*
 * Create the listening socket transport
 *
 * @return 0 for success
 */
int
sesman_create_listening_transport(const struct config_sesman *cfg);

/**
 * Callback to process incoming SCP data
 */
int
sesman_scp_data_in(struct trans *self);

/**
 * Callback to process incoming EICP data
 */
int
sesman_eicp_data_in(struct trans *self);

/**
 * Callback to process incoming ERCP data
 */
int
sesman_ercp_data_in(struct trans *self);

/*
 * Check for termination
 */
int
sesman_is_term(void);

#endif
