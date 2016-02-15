/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 * 
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies O脺
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * core structures
 */

#include "system.h"

#include <usual/time.h>
#include <usual/list.h>
#include <usual/statlist.h>
#include <usual/string.h>
#include <usual/logging.h>
#include <usual/aatree.h>
#include <usual/lookup3.h>
#include <usual/slab.h>
#include <usual/socket.h>
#include <usual/safeio.h>
#include <usual/mbuf.h>
#include <usual/strpool.h>
#include <proto/backend.h>
#include <proto/common.h>
#include <proto/frontend.h>
#include <proto/protooutput.h>
#include <pthread.h>
#include <stdio.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/event_compat.h>

#ifndef __linux
#define bool unsigned char
#define true 1
#define false 0
#endif
#ifndef __linux
#define size_t unsigned int
#endif

/* to avoid allocations will use static buffers */
#define MAX_DBNAME	64
#define MAX_USERNAME	64
#define MAX_PASSWORD	64
#define MAX_PGPARAM     512

#ifdef DBGVER
#define FULLVER   PACKAGE_NAME " version " PACKAGE_VERSION " (" DBGVER ")"
#else
#define FULLVER   PACKAGE_NAME " version " PACKAGE_VERSION
#endif

/* each state corresponts to a list */
enum SocketState {
	CL_INIT,        /*client init state*/
	CL_FREE,		/* free_client_list */
	CL_JUSTFREE,		/* justfree_client_list */
	CL_CONNECT,      /*connectList*/
	CL_LOGIN,		/* login_client_list */
	CL_WAITING,		/* pool->waiting_client_list */
	CL_OLDACTIVE,   /* pool->oldActive_list*/
	CL_ACTIVE,		/* pool->active_client_list */

	CL_CANCEL,		/* pool->cancel_req_list */
	CL_DISCONN,     /*need to run disconnect operation*/
	CL_FINISH,     /*finished client state define*/

	SV_INIT,       /*server init state*/
	SV_FREE,		/* free_server_list */
	SV_JUSTFREE,		/* justfree_server_list */

	//server pool thread use state
	SV_LOGIN,		/* pool->new_server_list */

	SV_WAITING,      /* pool->logined_server_list add by huih@20150731 */
	SV_IDLE,		/* pool->idle_server_list */

	//client thread use state
	SV_ACTIVE,		/* pool->active_server_list */
	SV_OLDACTIVE,   /* pool->old_active_server_list */

	//client thread don't use server, first move server to middile state.
	SV_WAITTEST,   /*pool->waittest_server_list*/
	SV_TESTED,		/* pool->tested_server_list */
	SV_USED,		/* pool->used_server_list */


	//need to disconnect server
	SV_DISCONN,     /*need to run disconnect operation*/

	SV_FINISH,       /*finished server state define*/
};

enum PauseMode {
	P_NONE = 0,		/* active pooling */
	P_PAUSE = 1,		/* wait for client to finish work */
	P_SUSPEND = 2		/* wait for buffers to be empty */
};

#define is_server_socket(sk) ((sk)->state >= SV_INIT)

typedef struct PgSocket PgSocket;
typedef struct PgUser PgUser;
typedef struct PgDatabase PgDatabase;
typedef struct PgPool PgPool;
typedef struct PgStats PgStats;
typedef union PgAddr PgAddr;
typedef enum SocketState SocketState;
typedef struct PktHdr PktHdr;

extern int cf_sbuf_len;

/*
 * AF_INET,AF_INET6 are stored as-is,
 * AF_UNIX uses sockaddr_in port.
 */
union PgAddr {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

//add by huih@20150826
typedef struct PgOldSocket{
	struct List head;
	int fd;
	PgAddr addr;
	char dbName[MAX_DBNAME];
	char userName[MAX_USERNAME];
	uint64_t ckey;
	int oldfd;
	int linkfd;
	char client_enc[MAX_PGPARAM];
	char std_string[MAX_PGPARAM];
	char datestyle[MAX_PGPARAM];
	char timezone[MAX_PGPARAM];
}PgOldSocket;



/*add by huih@20150727*/
typedef void (*uevent_cb_f)(int fd, short flags, void *arg);
#define pgbouncer_event_set(base, ev, fd, flags, cb, arg) event_assign(ev, base, fd, flags, cb, arg);
#define pgbouncer_event_add(ev, timeout) event_add(ev, timeout);

#define pgbouncer_signal_set(base, ev, fd, cb, arg) \
		pgbouncer_event_set(base, ev, fd, EV_SIGNAL | EV_PERSIST, cb, arg);
#define pgbouncer_signal_add(ev, timeout) pgbouncer_event_add(ev, timeout);

#define pgbouncer_evtimer_set(base, ev, cb, arg) \
		pgbouncer_event_set(base, ev, -1, 0, cb, arg);
#define pgbouncer_evtimer_add(ev, timeout) pgbouncer_event_add(ev, timeout);



#include "util.h"
#include "iobuf.h"
#include "sbuf.h"
#include "pktbuf.h"
#include "varcache.h"
#include "dnslookup.h"

#include "admin.h"
#include "loader.h"
#include "client.h"
#include "server.h"
#include "pooler.h"
#include "proto.h"
#include "objects.h"
#include "stats.h"
#include "takeover.h"
#include "janitor.h"
#include "multhreads/clientthreads.h"
#include "multhreads/serverpool.h"
#include "multhreads/acceptthread.h"
#include "multhreads/pgthread.h"
#include "multhreads/vipthread.h"
#include "proto/backend.h"
#include "proto/common.h"
#include "proto/frontend.h"
#include "proto/protooutput.h"
#include "testserverpool.h"


/* auth modes, should match PG's
 *  */
#define AUTH_ANY	-1 /* same as trust but without username check */
#define AUTH_TRUST	0
#define AUTH_PLAIN	3
#define AUTH_CRYPT	4
#define AUTH_MD5	5
#define AUTH_CREDS	6

/* type codes for weird pkts */
#define PKT_STARTUP_V2  0x20000
#define PKT_STARTUP     0x30000
#define PKT_CANCEL      80877102
#define PKT_SSLREQ      80877103

#define POOL_SESSION	0
#define POOL_TX		1
#define POOL_STMT	2

/* old style V2 header: len:4b code:4b */
#define OLD_HEADER_LEN	8
/* new style V3 packet header len - type:1b, len:4b */ 
#define NEW_HEADER_LEN	5

#define BACKENDKEY_LEN	8

/* buffer size for startup noise */
#define STARTUP_BUF	1024


/*
 * Remote/local address
 */

/* buffer for pgaddr string conversions (with port) */
#define PGADDR_BUF  (INET6_ADDRSTRLEN + 10)

static inline bool pga_is_unix(const PgAddr *a) { return a->sa.sa_family == AF_UNIX; }

int pga_port(const PgAddr *a);
void pga_set(PgAddr *a, int fam, int port);
void pga_copy(PgAddr *a, const struct sockaddr *sa);
bool pga_pton(PgAddr *a, const char *s, int port);
const char *pga_ntop(const PgAddr *a, char *dst, int dstlen);
const char *pga_str(const PgAddr *a, char *dst, int dstlen);
int pga_cmp_addr(const PgAddr *a, const PgAddr *b);

/*
 * A user in login db.
 *
 * fixme: remove ->head as ->tree_node should be enough.
 *
 * For databases where remote user is forced, the pool is:
 * first(db->forced_user->pool_list), where pool_list has only one entry.
 *
 * Otherwise, ->pool_list contains multiple pools, for all PgDatabases
 * whis user has logged in.
 */
struct PgUser {
	struct List head;		/* used to attach user to list */
	struct List pool_list;		/* list of pools where pool->user == this user */
	struct AANode tree_node;	/* used to attach user to tree */
	char name[MAX_USERNAME];
	char passwd[MAX_PASSWORD];
};

/*
 * A database entry from config.
 */
struct PgDatabase {
	struct List head;
	char name[MAX_DBNAME];	/* db name for clients */

	bool db_paused;		/* PAUSE <db>; was issued */
	bool db_dead;		/* used on RELOAD/SIGHUP to later detect removed dbs */
	bool db_auto;		/* is the database auto-created by autodb_connstr */
	bool admin;		/* internal console db */

	struct PktBuf *startup_params; /* partial StartupMessage (without user) be sent to server */

	PgUser *forced_user;	/* if not NULL, the user/psw is forced */

	const char *host;	/* host or unix socket name */
	int port;

	int pool_size;		/* max server connections in one pool */
	int res_pool_size;	/* additional server connections in case of trouble */

	const char *dbname;	/* server-side name, pointer to inside startup_msg */

	/* startup commands to send to server after connect. malloc-ed */
	const char *connect_query;

	usec_t inactive_time;	/* when auto-database became inactive (to kill it after timeout) */
	unsigned active_stamp;	/* set if autodb has connections */
};


/*
 * A client or server connection.
 *
 * ->state corresponds to various lists the struct can be at.
 */
struct PgSocket {
	struct List head;		/* list header */
	struct List client_thread_head; /*client thread head, when the socket is server ,need use it*/

	PgSocket *link;		/* the dest of packets */
	PgPool *pool;		/* parent pool, if NULL not yet assigned */

	PgUser *auth_user;	/* presented login, for client it may differ from pool->user */

	SocketState state:8;	/* this also specifies socket location */

	bool ready:1;		/* server: accepts new query */
	bool idle_tx:1;		/* server: idling in tx */
	bool close_needed:1;	/* server: this socket must be closed ASAP */
	bool setting_vars:1;	/* server: setting client vars */
	bool exec_on_connect:1;	/* server: executing connect_query */

	bool wait_for_welcome:1;/* client: no server yet in pool, cannot send welcome msg */

	bool suspended:1;	/* client/server: if the socket is suspended */

	bool admin_user:1;	/* console client: has admin rights */
	bool own_user:1;	/* console client: client with same uid on unix socket */
	bool wait_for_response:1;/* console client: waits for completion of PAUSE/SUSPEND cmd */
	bool disconn_notify:1;/*when disconnect, send terminate message or not*/
	char *disconn_reason; /*disconnect reason*/

	usec_t connect_time;	/* when connection was made */
	usec_t request_time;	/* last activity time */
	usec_t query_start;	/* query start moment */
	usec_t client_idle_time; /*wait client to use the server time,add by huih@20150825*/

	uint8_t cancel_key[BACKENDKEY_LEN]; /* client: generated, server: remote */
	PgAddr remote_addr;	/* ip:port for remote endpoint */
	PgAddr local_addr;	/* ip:port for local endpoint */

	struct DNSToken *dns_token;	/* ongoing request */

	VarCache vars;		/* state of interesting server parameters */

	SBuf sbuf;		/* stream buffer, must be last */

	PgCLThread* thread; /*current using multhread, add by huih@20150727*/
	PgCLThread* createSocketThread; /*add by huih@20150802, create the socket thread info*/

	int index;/*index for server pgsocket add by huih@20150729*/
	int fd; //connect file decriptor add by huih@20150729
	bool is_unix; // add by huih@20150729
	bool is_block:1; // is block or not
	bool is_server:1; //is server or client
	bool is_free:1;

	//add by huih@20150826
	usec_t old_fd;
	usec_t old_linkFd;
};

#define RAW_IOBUF_SIZE	offsetof(IOBuf, buf)
#define IOBUF_SIZE	(RAW_IOBUF_SIZE + cf_sbuf_len)

/* where to store old fd info during SHOW FDS result processing */
#define tmp_sk_oldfd	old_fd
#define tmp_sk_linkfd	old_linkFd
/* takeover_clean_socket() needs to clean those up */

/* where the salt is temporarly stored */
#define tmp_login_salt  cancel_key

/* main.c */
extern int cf_daemon;

extern char *cf_config_file;
extern char *cf_jobname;

extern char *cf_unix_socket_dir;
extern int cf_unix_socket_mode;
extern char *cf_unix_socket_group;
extern char *cf_listen_addr;
extern int cf_listen_port;
extern int cf_listen_backlog;

extern int cf_pool_mode;
extern int cf_max_client_conn;
extern int cf_default_pool_size;
extern int cf_min_pool_size;
extern int cf_res_pool_size;
extern usec_t cf_res_pool_timeout;

extern char * cf_autodb_connstr;
extern usec_t cf_autodb_idle_timeout;

extern usec_t cf_suspend_timeout;
extern usec_t cf_server_lifetime;
extern usec_t cf_server_idle_timeout;
extern char * cf_server_reset_query;
extern char * cf_server_check_query;
extern usec_t cf_server_check_delay;
extern usec_t cf_server_connect_timeout;
extern usec_t cf_server_login_retry;
extern usec_t cf_query_timeout;
extern usec_t cf_query_wait_timeout;
extern usec_t cf_client_idle_timeout;
extern usec_t cf_client_login_timeout;
extern usec_t cf_idle_transaction_timeout;
extern int cf_server_round_robin;
extern int cf_disable_pqexec;
extern usec_t cf_dns_max_ttl;
extern usec_t cf_dns_zone_check_period;

extern int cf_auth_type;
extern char *cf_auth_file;

extern char *cf_pidfile;

extern char *cf_ignore_startup_params;

extern char *cf_admin_users;
extern char *cf_stats_users;
extern int cf_stats_period;

extern int cf_pause_mode;
extern int cf_shutdown;
extern int cf_reboot;

extern unsigned int cf_max_packet_size;

extern int cf_sbuf_loopcnt;
extern int cf_tcp_keepalive;
extern int cf_tcp_keepcnt;
extern int cf_tcp_keepidle;
extern int cf_tcp_keepintvl;
extern int cf_tcp_socket_buffer;
extern int cf_tcp_defer_accept;

extern int cf_log_connections;
extern int cf_log_disconnections;
extern int cf_log_pooler_errors;

extern int cf_threads_num;//the number of threads in config file
extern usec_t cf_client_server_idle_timeout; //add by huih@20150825
extern usec_t cf_oldBouncer_socket_link_timeout; //add by huih@20150827
extern char* cf_ha_interface_vip; //add by huih@20150831
extern char* cf_ha_interface_name; //add by huih@20150831
extern PgThread *pMainThread; //main thread

extern usec_t g_suspend_start;

extern struct DNSContext *adns;
extern const char* pgbouncer_dbname;

static inline PgSocket * _MUSTCHECK
pop_socket(struct StatList *slist)
{
	struct List *item = statlist_pop(slist);
	if (item == NULL)
		return NULL;
	return container_of(item, PgSocket, head);
}

static inline PgSocket *
first_socket_safe(pthread_mutex_t* mutex, struct StatList *slist)
{
	PgSocket *pgSocket = NULL;
	pthread_mutex_lock(mutex);
	if (!statlist_empty(slist))
		pgSocket = container_of(slist->head.next, PgSocket, head);
	pthread_mutex_unlock(mutex);
	return pgSocket;
}

static inline PgSocket *
first_socket(struct StatList *slist)
{
	PgSocket *pgSocket = NULL;
	if (!statlist_empty(slist))
		pgSocket = container_of(slist->head.next, PgSocket, head);
	return pgSocket;
}

void load_config(void);

bool set_config_param(const char *key, const char *val);
void config_for_each(void (*param_cb)(void *arg, const char *name, const char *val, bool reloadable),
		     void *arg);

int pgbouncer_add_signal_event(struct event_base *base, struct event *ev,
		int fd, uevent_cb_f cb, void *arg, struct timeval *timeout);
