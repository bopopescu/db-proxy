/* $%BEGINLICENSE%$
 Copyright (c) 2008, 2009, Oracle and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 of the
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */
#ifndef _NETWORK_MYSQLD_MASTERINFO_H_
#define _NETWORK_MYSQLD_MASTERINFO_H_

#include <glib.h>

#include "network-exports.h"
#include "network-mysqld-proto.h"

typedef struct {
    guint32   oligarch_lines;
    GString  *oligarch_log_file;
    guint32   oligarch_log_pos;
    GString  *oligarch_host;
    GString  *oligarch_user;
    GString  *oligarch_password;
    guint32   oligarch_port;
    guint32   oligarch_connect_retry;

    guint32   oligarch_ssl;          /* if ssl is compiled in */
    GString  *oligarch_ssl_ca;
    GString  *oligarch_ssl_capath;
    GString  *oligarch_ssl_cert;
    GString  *oligarch_ssl_cipher;
    GString  *oligarch_ssl_key;

    guint32   oligarch_ssl_verify_server_cert; /* 5.1.16+ */
} network_mysqld_oligarchinfo_t;

NETWORK_API network_mysqld_oligarchinfo_t * network_mysqld_oligarchinfo_new(void);
NETWORK_API int network_mysqld_oligarchinfo_get(network_packet *packet, network_mysqld_oligarchinfo_t *info);
NETWORK_API int network_mysqld_oligarchinfo_append(GString *packet, network_mysqld_oligarchinfo_t *info);
NETWORK_API void network_mysqld_oligarchinfo_free(network_mysqld_oligarchinfo_t *info);

#endif
