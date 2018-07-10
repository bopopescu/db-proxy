/* $%BEGINLICENSE%$
 Copyright (c) 2007, 2009, Oracle and/or its affiliates. All rights reserved.

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
 

#ifndef _NETWORK_SOCKET_H_
#define _NETWORK_SOCKET_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network-exports.h"
#include "network-queue.h"

#ifdef HAVE_SYS_TIME_H
/**
 * event.h needs struct timeval and doesn't include sys/time.h itself
 */
#include <sys/time.h>
#endif

#include <linux/version.h>
#include <sys/types.h>      /** u_char */
#ifndef _WIN32
#include <sys/socket.h>     /** struct sockaddr */

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>     /** struct sockaddr_in */
#endif
#include <netinet/tcp.h>

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>         /** struct sockaddr_un */
#endif
/**
 * use closesocket() to close sockets to be compatible with win32
 */
#define closesocket(x) close(x)
#else
#include <winsock2.h>
#include <Ws2tcpip.h>
#endif
#include <glib.h>
#include <event.h>

#include "network-address.h"

typedef enum {
    NETWORK_SOCKET_SUCCESS,
    NETWORK_SOCKET_WAIT_FOR_EVENT,
    NETWORK_SOCKET_ERROR,
    NETWORK_SOCKET_ERROR_RETRY
} network_socket_retval_t;

typedef enum {
    AUTOCOMMIT_UNKNOWN,
    AUTOCOMMIT_TRUE,
    AUTOCOMMIT_FALSE
} network_socket_autocommit_t;

typedef enum {
    SOCKET_LISTEN,
    SOCKET_SERVER,
    SOCKET_CLIENT
} network_socket_dir_t;

typedef struct{
    GString *default_db;
    network_socket_autocommit_t autocommit_status;
    gboolean savepoint_flag;                  
    GQueue* set_vars;                        // 当前设置的系统变量列表
    GString* charset_client;
    GString* charset_results;
    GString* charset_connection;
} conn_attr_t;

typedef struct network_mysqld_auth_challenge network_mysqld_auth_challenge;
typedef struct network_mysqld_auth_response network_mysqld_auth_response;

typedef struct {
    int fd;             /**< socket-fd */
    struct event event; /**< events for this fd */

    network_address *src; /**< getsockname() */
    network_address *dst; /**< getpeername() */

    int socket_type; /**< SOCK_STREAM or SOCK_DGRAM for now */

    void *srv;
    network_socket_dir_t socket_dir;

    guint64 ts_connected;  // the time to create socket

    guint8   last_packet_id; /**< internal tracking of the packet_id's the automaticly set the next good packet-id */
    gboolean packet_id_is_reset; /**< internal tracking of the packet_id sequencing */

    network_queue *recv_queue;
    network_queue *recv_queue_raw;
    network_queue *send_queue;

    off_t header_read;
    off_t to_read;
    
    /**
     * data extracted from the handshake  
     *
     * all server-side only
     */
    network_mysqld_auth_challenge *challenge;
    network_mysqld_auth_response  *response;

    conn_attr_t conn_attr;

    gboolean is_authed;           /** did a client already authed this connection */
} network_socket;

#define EMPTYSTR    ""
#define NOCLIENT    EMPTYSTR
#define NOBACKEND   EMPTYSTR
#define NOUSR       EMPTYSTR
#define NODB        EMPTYSTR
#define INVALID_THID    0

#define NETWORK_SOCKET_SRC_NAME(ns)     ((ns) ? (ns)->src->name->str : NOCLIENT)
#define NETWORK_SOCKET_DST_NAME(ns)     ((ns) ? (ns)->dst->name->str : NOBACKEND)
#define NETWORK_SOCKET_USR_NAME(ns)     ((ns) ? ((ns)->response ? (ns)->response->username->str : NOUSR) : NOUSR)
#define NETWORK_SOCKET_THREADID(ns)     ((ns) ? ((ns)->challenge ? (ns)->challenge->thread_id : INVALID_THID) : INVALID_THID)
#define NETWORK_SOCKET_DB_NAME(ns)      ((ns) ?  (ns)->conn_attr.default_db->str:NODB)
#define NETWORK_SOCKET_SRC_IPADDR(ns)     ((ns) ? inet_ntoa((ns)->src->addr.ipv4.sin_addr) : EMPTYSTR)

NETWORK_API network_socket *network_socket_init(void) G_GNUC_DEPRECATED;
NETWORK_API network_socket *network_socket_new(network_socket_dir_t socket_dir);
NETWORK_API void network_socket_free(network_socket *s);
NETWORK_API void network_socket_set_chassis(network_socket *s, void *srv);
NETWORK_API network_socket_retval_t network_socket_write(network_socket *con, int send_chunks);
NETWORK_API network_socket_retval_t network_socket_read(network_socket *con);
NETWORK_API network_socket_retval_t network_socket_to_read(network_socket *sock);
NETWORK_API network_socket_retval_t network_socket_set_non_blocking(network_socket *sock);
NETWORK_API network_socket_retval_t network_socket_connect(network_socket *con);
NETWORK_API network_socket_retval_t network_socket_connect_finish(network_socket *sock);
NETWORK_API network_socket_retval_t network_socket_bind(network_socket *con);
NETWORK_API network_socket *network_socket_accept(network_socket *srv);
NETWORK_API network_socket_retval_t network_socket_connect_setopts(network_socket *sock);

#endif

