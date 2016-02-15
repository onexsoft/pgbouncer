/*
 * multhreadpools.h
 *
 *  Created on: 2015730
 *      Author: April
 */

#ifndef INCLUDE_MULTHREADS_SERVERPOOL_H_
#define INCLUDE_MULTHREADS_SERVERPOOL_H_

extern struct StatList justfree_server_list;
extern struct StatList oldServerSocket_list;

/*
 * Stats, kept per-pool.
 */
struct PgStats {
	uint64_t request_count;
	uint64_t server_bytes;
	uint64_t client_bytes;
	usec_t query_time;	/* total req time in us */
};

/*
 * Contains connections for one db+user pair.
 *
 * Stats:
 *   ->stats is updated online.
 *   for each stats_period:
 *   ->older_stats = ->newer_stats
 *   ->newer_stats = ->stats
 */
struct PgPool {
	struct List head;			/* entry in global pool_list */
	struct List map_head;			/* entry in user->pool_list */

	PgDatabase *db;			/* corresponging database */
	PgUser *user;			/* user logged in as */

	struct StatList active_server_list;	 /* servers linked with clients */
	struct StatList idle_server_list;	   /* servers ready to be linked with clients */
	struct StatList used_server_list;	   /* server just unlinked from clients */
	struct StatList waittest_server_list;  /* server wait test server list*/
	struct StatList tested_server_list;	 /* server in testing process */
	struct StatList new_server_list;	   /* servers in login phase*/
	struct StatList wait_server_list;    /* server receive backend readyforQuery message,
	                                      but process not success,need to wait a while*/
	struct StatList cancel_server_list; /*backend cancel server request list*/
	struct StatList disconnect_server_list;/*need to run disconnect operation*/
	struct StatList old_active_server_list;/*when use -R parameter, need to use it*/

	PgStats stats;
	PgStats newer_stats;
	PgStats older_stats;

	/* database info to be sent to client */
	struct PktBuf *welcome_msg; /* ServerParams without VarCache ones */

	VarCache orig_vars;		/* default params from server */

	usec_t last_lifetime_disconnect;/* last time when server_lifetime was applied */

	/* if last connect failed, there should be delay before next */
	usec_t last_connect_time;
	unsigned last_connect_failed:1;

	unsigned welcome_msg_ready:1;

	pthread_mutex_t poolMutex; //control multhread
	pthread_cond_t poolCond;

	PgThread* thread;
	unsigned int serverNum; //current pool have servers number;
};

#define pool_server_count(pool) ( \
		statlist_count(&(pool)->active_server_list) + \
		statlist_count(&(pool)->idle_server_list) + \
		statlist_count(&(pool)->new_server_list) + \
		statlist_count(&(pool)->tested_server_list) + \
		statlist_count(&(pool)->used_server_list))


//init server pool thread
int init_serverPool(void);

//provide a idle server
PgSocket* get_server_from_pool(PgPool* pool);

//destroy pool thread
void destory_serverPool(void);

//add by huih@20150826
void add_serverOldSocket(PgOldSocket *pgOldSocket);

//shut down server pool thread, add by huih@20150827
void shutdown_serverPool(void);

//link client to server, add by huih@20150828
bool link_client_server(PgSocket* client);

#endif /* INCLUDE_MULTHREADS_SERVERPOOL_H_ */
