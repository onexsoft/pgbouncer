/*
 * serverpool.c
 *
 *  Created on: 2015/07/30
 *      Author: April
 */
#include "bouncer.h"

static PgThread *pPoolThread;
STATLIST(justfree_server_list);
STATLIST(oldServerSocket_list);

/* async dns handler */
struct DNSContext *adns;

static struct timeval serverPool_full_maint_period = {0, USEC/3};
static struct event serverPool_full_maint_ev;

static void* worker_thread(void* arg);
static void launch_connection(PgThread *pgThread);
static void maint_global_control(void);
static void pause_serverPool(PgPool *pool);
static void activate_serverPool(PgPool *pool);
static void suspend_serverPool(PgPool *pool, bool force_suspend);
static void recycle_serverPool_socket(void);
static void setup_serverPool_janitor(PgThread *pgThread);
static int sum_serverPool(PgPool *pool);
static void release_serverPool_socket(PgThread *pgThread);
static void setup_dns(PgThread *pgThread);
static void do_serverPool_maint(int sock, short flags, void *arg);
static void do_serverPool_waittest(void);
static int handle_oldServerSocket(PgThread *pgThread);
//check old bouncer socket timeout
static void check_oldServerSocketTimeout(PgPool *pgPool);

int init_serverPool(void)
{
	int err = 0;

	pPoolThread = new_pgThread("server pool thread");
	if (pPoolThread == NULL) {
		log_error("pPoolThread == NULL");
		return -1;
	}

	err = pthread_create(&pPoolThread->tid, NULL, worker_thread ,pPoolThread);
	if (err) {
		log_error("create thread error\n");
		return -1;
	}

	return 0;
}

static void* worker_thread(void* arg)
{
	int err = 0;
	PgThread *pgThread = arg;

	Assert(pgThread != NULL);

	setup_dns(pgThread);
	//serverPool_new_pool();

	setup_serverPool_janitor(pgThread);

	//add monitor
	serverPool_monitor(pgThread);

	//add by huih@20150826
	err = handle_oldServerSocket(pgThread);
	if (err < 0) {
		return (void*)-1;
	}

	while(cf_shutdown < 2) {
		err = event_base_loop(pgThread->eventBase, EVLOOP_ONCE);
		if (err < 0) {
			log_error("event_base_loop error");
			return (void*)-1;
		}

		recycle_serverPool_socket();

		//launch connection
		launch_connection(pgThread);

		//run timing event
		run_timerEvent(pgThread);

		//test waittest server
		do_serverPool_waittest();

		//disconnect server
		release_serverPool_socket(pgThread);
	}
	return (void*)0;
}

static void launch_connection(PgThread *pgThread)
{
	struct List *item;
	PgPool *pPgPool;
	int sum_current_server = 0;

	Assert(pgMulThread != NULL);
	statlist_for_each(item, &pool_list) {
		pPgPool = container_of(item, PgPool, head);
		pPgPool->thread = pgThread;
		if (!strcmp(pPgPool->db->dbname, pgbouncer_dbname)) {
			continue;
		}
		//check idle list
		sum_current_server = sum_serverPool(pPgPool);
		if (!is_pause_mode
				&& sum_current_server < pPgPool->db->pool_size
				&& statlist_count(&pPgPool->idle_server_list) < 2//pPgPool->db->res_pool_size
				&& statlist_count(&pPgPool->new_server_list) <= 0) {
			launch_new_connection(pPgPool);
		}
	}
}

PgSocket* get_server_from_pool(PgPool* pool)
{
	PgSocket* server = NULL;

	if (statlist_count(&pool->idle_server_list) <= 0 || cf_pause_mode == P_SUSPEND) {
		return server;
	}

	pthread_mutex_lock(&pool->poolMutex);
	do {
		if (statlist_count(&pool->idle_server_list) <= 0) {
			break;
		}
		server = container_of(pool->idle_server_list.head.next, PgSocket, head);
		change_server_state(server, SV_ACTIVE);
	} while(0);
	pthread_mutex_unlock(&pool->poolMutex);

	return server;
}

void destory_serverPool(void)
{
	struct List *item, *tmp;
	struct PgOldSocket *pgOldSocket = NULL;
	struct PgPool *pgPool = NULL;

	pthread_join(pPoolThread->tid, NULL);
	destroy_pgThread(pPoolThread);

	while(statlist_count(&oldServerSocket_list) > 0) {
		pgOldSocket = container_of(
				statlist_pop(&oldServerSocket_list), PgOldSocket, head);
		free(pgOldSocket);
	}

	//clean pool socket
	statlist_for_each_safe(item, &pool_list, tmp) {
		pgPool = container_of(item, PgPool, head);
		if (cf_pause_mode != P_SUSPEND) {
			close_server_list(&pgPool->active_server_list, "shutdown, close server socket");
			close_server_list(&pgPool->old_active_server_list, "shutdown, close server socket");
		}
		close_server_list(&pgPool->idle_server_list, "shutdown, close server socket");
		close_server_list(&pgPool->waittest_server_list, "shutdown, close server socket");
		close_server_list(&pgPool->wait_server_list, "shutdown, close server socket");
		close_server_list(&pgPool->tested_server_list, "shutdown, close server socket");
		close_server_list(&pgPool->used_server_list, "shutdown, close server socket");
		close_server_list(&pgPool->disconnect_server_list, "shutdown, close server socket");
		close_server_list(&pgPool->new_server_list, "shutdown, close server socket");
	}
	release_serverPool_socket(NULL);
}

static void maint_global_control(void)
{
	struct List *item;
	PgPool *pool;
	bool force_suspend = false;

	if (cf_pause_mode == P_SUSPEND && cf_suspend_timeout > 0) {
		usec_t stime = get_cached_time() - g_suspend_start;
		if (stime >= cf_suspend_timeout)
			force_suspend = true;
	}

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db->admin)
			continue;
		switch (cf_pause_mode) {
		case P_NONE:
			if (pool->db->db_paused) {
				pause_serverPool(pool);//
			} else
				activate_serverPool(pool);//
			break;
		case P_PAUSE:
			pause_serverPool(pool);
			break;
		case P_SUSPEND:
			suspend_serverPool(pool, force_suspend);
			break;
		}
	}
}

static void pause_serverPool(PgPool *pool)
{
	if (pool->db->admin)
		return;

	close_server_list(&pool->idle_server_list, "pause mode");
	close_server_list(&pool->used_server_list, "pause mode");
	close_server_list(&pool->new_server_list, "pause mode");
}

static void activate_serverPool(PgPool *pool)
{
	if (!statlist_empty(&pool->used_server_list)) {
		launch_recheck(pool);
	}

	//add by huih@20150826, resume_sockets
	resume_socket_list(&pool->active_server_list);
	resume_socket_list(&pool->idle_server_list);
}

static void suspend_serverPool(PgPool *pool, bool force_suspend)
{
	int active = 0;

	if (pool->db->admin)
		return;

	if (active)
		activate_serverPool(pool);

	if (!active) {
		active += suspend_socket_list(&pool->active_server_list, force_suspend);
		active += suspend_socket_list(&pool->idle_server_list, force_suspend);
		active += suspend_socket_list(&pool->old_active_server_list, force_suspend);

		/* as all clients are done, no need for them */
		close_server_list(&pool->tested_server_list, "close unsafe file descriptors on suspend");
		close_server_list(&pool->used_server_list, "close unsafe file descriptors on suspend");
		close_server_list(&pool->wait_server_list, "close unsafe file descriptors on suspend");
		close_server_list(&pool->waittest_server_list, "close unsafe file descriptors on suspend");

	}
	return;
}

static void recycle_serverPool_socket(void)
{
	struct List *tmp, *item;
	PgSocket *sk;
	bool close_works = true;

	statlist_for_each_safe(item, &justfree_server_list, tmp) {
		sk = container_of(item, PgSocket, head);
		if (sbuf_is_closed(&sk->sbuf)) {
			change_server_state(sk, SV_FREE);
		}
		else if (close_works)
			close_works = sbuf_close(&sk->sbuf);
	}
}

static void setup_serverPool_janitor(PgThread *pgThread)
{
	/* launch maintenance */
	Assert(pgMulThread != NULL);
	pgbouncer_evtimer_set(pgThread->eventBase,
			&serverPool_full_maint_ev,
			do_serverPool_maint, pgThread);

	add_safe_evtimer(pgThread, &serverPool_full_maint_ev,
			&serverPool_full_maint_period);
}

void do_serverPool_maint(int sock, short flags, void *arg)
{
	struct List *item, *tmp;
	PgPool *pool;
	PgThread *pgThread;
	static unsigned int seq;
	seq++;

	pgThread = arg;
	Assert(pgMulThread != NULL);
	/*
	 * Avoid doing anything that may surprise other pgbouncer.
	 */
	if (cf_pause_mode == P_SUSPEND)
		goto skip_maint;

	statlist_for_each_safe(item, &pool_list, tmp) {
		pool = container_of(item, PgPool, head);
		if (pool->db->admin)
			continue;
		pool_server_maint(pool);
		check_pool_size(pool);

		check_oldServerSocketTimeout(pool);

		/* is autodb active? */
		if (pool->db->db_auto && pool->db->inactive_time == 0) {
			if (pool_server_count(pool) > 0)
				pool->db->active_stamp = seq;
		}
	}

	adns_zone_cache_maint(adns);

	if (cf_shutdown == 1 && get_active_server_count() == 0) {
		log_info("server connections dropped, exiting");
		cf_shutdown = 2;
		event_loopbreak();
		return;
	}

	maint_global_control();

skip_maint:
	add_safe_evtimer(pgThread, &serverPool_full_maint_ev, &serverPool_full_maint_period);
}

static int sum_serverPool(PgPool *pool)
{
	return pool->serverNum;
}

static void release_serverPool_socket(PgThread *pgThread)
{
	PgPool *pPgPool;
	struct List *item, *skItem;
	PgSocket *server;


	//LOG_TRACE_RUN_IN
	statlist_for_each(item, &pool_list) {
		pPgPool = container_of(item, PgPool, head);
		if (pPgPool->db->admin)
			continue;

		if (statlist_count(&pPgPool->disconnect_server_list) <= 0)
			continue;

		pthread_mutex_lock(&pPgPool->poolMutex);
		while(statlist_count(&pPgPool->disconnect_server_list) > 0) {
			skItem = statlist_first(&pPgPool->disconnect_server_list);
			server = container_of(skItem, PgSocket, head);
			disconnect_server(server, server->disconn_notify, "%s", server->disconn_reason);
			if (server->disconn_reason) {
				free(server->disconn_reason);
				server->disconn_reason = NULL;
			}
			change_server_state(server, SV_JUSTFREE);
		}
		pthread_mutex_unlock(&pPgPool->poolMutex);
	}
}

static void setup_dns(PgThread *pgThread)
{
	if (adns)
		return;
	adns = adns_create_context(pgThread);
	if (!adns)
		fatal_perror("dns setup failed");
}

static void do_serverPool_waittest(void)
{
	PgPool *pPgPool;
	struct List *item;

	statlist_for_each(item, &pool_list) {
		pPgPool = container_of(item, PgPool, head);
		if (pPgPool->db->admin)
			continue;
		handing_pool_waitTestServer(pPgPool);
	}
}

void add_serverOldSocket(PgOldSocket *pgOldSocket)
{
	statlist_append(&oldServerSocket_list, &pgOldSocket->head);
}

//add by huih@20150826
static int handle_oldServerSocket(PgThread *pgThread)
{
	PgOldSocket *pgOldSocket = NULL;
	int err = 0;

	while(statlist_count(&oldServerSocket_list) > 0) {
		pgOldSocket = container_of(statlist_pop(&oldServerSocket_list), PgOldSocket, head);
		err = use_server_socket(pgOldSocket->fd, &pgOldSocket->addr,
				pgOldSocket->dbName, pgOldSocket->userName, pgOldSocket->ckey,
				pgOldSocket->oldfd, pgOldSocket->linkfd, pgOldSocket->client_enc,
				pgOldSocket->std_string, pgOldSocket->datestyle, pgOldSocket->timezone, pgThread);
		if (!err) {
			free(pgOldSocket);
			return -1;
		}
		free(pgOldSocket);
	}
	return 0;
}

//add by huih@20150826
bool link_client_server(PgSocket* client)
{
	struct List *item, *tmp;
	PgSocket *server = NULL;

	if (NULL == client || NULL == client->pool)
		return false;

	pthread_mutex_lock(&client->pool->poolMutex);
	statlist_for_each_safe(item, &client->pool->old_active_server_list, tmp) {
		server = container_of(item, PgSocket, head);
		if (server->old_fd == client->old_linkFd){
			client->link = server;
			server->link = client;
			server->thread = client->thread;
			slog_debug(client, "client.sock: %d, server.sock: %d", client->fd, server->fd);
			change_server_state(server, SV_ACTIVE);
			change_client_state(client, CL_ACTIVE);
			break;
		}
	}
	pthread_mutex_unlock(&client->pool->poolMutex);
	return server == NULL ? false : true;
}

static void check_oldServerSocketTimeout(PgPool *pgPool)
{
	struct List *item, *tmp;
	PgSocket *server;
	usec_t now;

	if (statlist_count(&pgPool->old_active_server_list) <= 0)
		return;

	now = get_cached_time();
	pthread_mutex_lock(&pgPool->poolMutex);
	statlist_for_each_safe(item, &pgPool->old_active_server_list, tmp) {
		server = container_of(item, PgSocket, head);
		if (now - server->request_time > cf_oldBouncer_socket_link_timeout) {
			release_disconn_pgSocket(server, SV_DISCONN, 0, "no use old active server");
		}
	}
	pthread_mutex_unlock(&pgPool->poolMutex);
}

void shutdown_serverPool(void)
{
	shutdown_pgThread(pPoolThread);
}
