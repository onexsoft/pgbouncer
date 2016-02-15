/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 * 
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies
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
 * Periodic maintenance.
 */

#include "bouncer.h"

/* do full maintenance 3x per second */
static struct timeval full_maint_period = {0, USEC / 3};
static struct event full_maint_ev;

/* close all sockets in server list */
void close_server_list(struct StatList *sk_list, const char *reason)
{

	struct List *item, *tmp;
	PgSocket *server;

	statlist_for_each_safe(item, sk_list, tmp) {
		server = container_of(item, PgSocket, head);
//		release_disconn_pgSocket(server, SV_DISCONN, true, "%s", reason);
		disconnect_server(server, 0, "%s", reason);
	}
}

void close_client_list(struct StatList *sk_list, const char *reason)
{

	struct List *item, *tmp;
	PgSocket *client;

	statlist_for_each_safe(item, sk_list, tmp) {
		client = container_of(item, PgSocket, head);
		release_disconn_pgSocket(client, CL_DISCONN, true, reason);
	}
}

void close_reqtimeout_client_list(struct StatList *sk_list, const char *reason)
{
	struct List *item, *tmp;
	PgSocket *client;
	usec_t now;

	now = get_cached_time();
	statlist_for_each_safe(item, sk_list, tmp) {
		client = container_of(item, PgSocket, head);
		if (client->link)
			continue;
		if (now - client->request_time > cf_client_idle_timeout) {
			release_disconn_pgSocket(client, CL_DISCONN, true, reason);
		}
	}
}

void close_conntimeout_client_list(struct StatList *sk_list, const char *reason)
{
	struct List *item, *tmp;
	PgSocket *client;
	usec_t now;

	now = get_cached_time();
	statlist_for_each_safe(item, sk_list, tmp) {
		client = container_of(item, PgSocket, head);
		if (client->link)
			continue;
		if (now - client->connect_time > cf_client_idle_timeout) {
			release_disconn_pgSocket(client, CL_DISCONN, true, reason);
		}
	}
}

bool suspend_socket(PgSocket *sk, bool force_suspend)
{
	if (sk->suspended) {
		return true;
	}

	if (sbuf_is_empty(&sk->sbuf)) {
		log_error("sk.index: %d, sk.state: %d, sock: %d",
							sk->index, sk->state, sk->sbuf.sock);
		if (sbuf_pause(&sk->sbuf))
			sk->suspended = 1;
	}

	if (sk->suspended || !force_suspend)
		return sk->suspended;

	log_error("suspend_socket");
	if (is_server_socket(sk))
		release_disconn_pgSocket(sk, SV_DISCONN, true, "suspend_timeout");
	else
		release_disconn_pgSocket(sk, CL_DISCONN, true, "suspend_timeout");
	return true;
}

/* suspend all sockets in socket list */
int suspend_socket_list(struct StatList *list, bool force_suspend)
{
	struct List *item, *tmp;
	PgSocket *sk;
	int active = 0;

	statlist_for_each_safe(item, list, tmp) {
		sk = container_of(item, PgSocket, head);

		//no deal admin
		if (NULL != sk->pool && sk->pool->db->admin)
					continue;

		if (!suspend_socket(sk, force_suspend))
			active++;
	}
	return active;
}

void resume_socket_list(struct StatList *list)
{
	struct List *item, *tmp;
	PgSocket *sk;

	statlist_for_each_safe(item, list, tmp) {
		sk = container_of(item, PgSocket, head);
		if (sk->suspended) {
			sk->suspended = 0;
			log_error("sk.index: %d, sk.sock: %d", sk->index, sk->sbuf.sock);

			if (sk->state != CL_WAITING)
				sbuf_continue(&sk->sbuf);
		}
	}
}

/* resume pools and listen sockets */
void resume_all(void)
{

	//resume_sockets();
	//resume_pooler();
}

/*
 * send test/reset query to server if needed
 * main thread run the function
 */
void launch_recheck(PgPool *pool)
{
	const char *q = cf_server_check_query;
	bool need_check = true;
	PgSocket *server;
	bool res = true;

	/* find clean server */
	while (1) {
		server = first_socket(&pool->used_server_list);
		if (!server)
			return;
		if (server->ready)
			break;
		release_disconn_pgSocket(server, SV_DISCONN, true, "idle server got dirty");
	}

	/* is the check needed? */
	if (q == NULL || q[0] == 0)
		need_check = false;
	else if (cf_server_check_delay > 0) {
		usec_t now = get_cached_time();
		if (now - server->request_time < cf_server_check_delay)
			need_check = false;
	}

	if (need_check) {
		/* send test query, wait for result */
		slog_debug(server, "P: Checking: %s", q);
		change_server_state(server, SV_TESTED);
		SEND_generic(res, server, 'Q', "s", q);
		if (!res) {
			release_disconn_pgSocket(server, SV_DISCONN, false, "test query failed");
		}
	} else {
		/* make immediately available */
		log_debug("release_server immediately avvailable");
		release_server(server);
	}
}

static void check_unused_servers(PgPool *pool, struct StatList *slist, bool idle_test)
{
	usec_t now = get_cached_time();
	struct List *item, *tmp;
	usec_t idle, age;
	PgSocket *server;
	usec_t lifetime_kill_gap = 0;

	/*
	 * Calculate the time that disconnects because of server_lifetime
	 * must be separated.  This avoids the need to re-launch lot
	 * of connections together.
	 */
	if (pool->db->pool_size > 0)
		lifetime_kill_gap = cf_server_lifetime / pool->db->pool_size;

	/* disconnect idle servers if needed */
	pthread_mutex_lock(&pool->poolMutex);
	statlist_for_each_safe(item, slist, tmp) {
		server = container_of(item, PgSocket, head);

		age = now - server->connect_time;
		idle = now - server->request_time;

		if (server->close_needed) {
			release_disconn_pgSocket_unsafe(server, SV_DISCONN, true, "database configuration changed");
		} else if (server->state == SV_IDLE && !server->ready) {
			release_disconn_pgSocket_unsafe(server, SV_DISCONN, true, "SV_IDLE server got dirty");
		} else if (server->state == SV_USED && !server->ready) {
			release_disconn_pgSocket_unsafe(server, SV_DISCONN, true, "SV_USED server got dirty");
		} else if (cf_server_idle_timeout > 0 && idle > cf_server_idle_timeout) {
			log_error("now: %" PRIu64 ", request_time: %" PRIu64 ", idle: %" PRIu64 ", "
					"cf_server_idle_timeout: %" PRIu64 "\n",now,
					server->request_time, idle, cf_server_idle_timeout);
			release_disconn_pgSocket_unsafe(server, SV_DISCONN, true, "server idle timeout");
		} else if (age >= cf_server_lifetime) {
			if (pool->last_lifetime_disconnect + lifetime_kill_gap <= now) {
				release_disconn_pgSocket_unsafe(server, SV_DISCONN, true, "server lifetime over");
				pool->last_lifetime_disconnect = now;
			}
		} else if (cf_pause_mode == P_PAUSE) {
			release_disconn_pgSocket_unsafe(server, SV_DISCONN, true, "pause mode");
		} else if (idle_test && *cf_server_check_query) {
			if (idle > cf_server_check_delay)
				change_server_state(server, SV_USED);
		}
	}
	pthread_mutex_unlock(&pool->poolMutex);
}

/*
 * Check pool size, close conns if too many.  Makes pooler
 * react faster to the case when admin decreased pool size.
 * main thread call the function
 */
void check_pool_size(PgPool *pool)
{
	PgSocket *server;
	int cur = statlist_count(&pool->active_server_list)
		+ statlist_count(&pool->idle_server_list)
		+ statlist_count(&pool->used_server_list)
		+ statlist_count(&pool->tested_server_list)
		+ statlist_count(&pool->wait_server_list)
		+ statlist_count(&pool->disconnect_server_list);

		/* cancel pkt may create new srv conn without
		 * taking pool_size into account
		 *
		 * statlist_count(&pool->new_server_list)
		 */

	int many = cur - (pool->db->pool_size + pool->db->res_pool_size);

	Assert(pool->db->pool_size >= 0);

	while (many > 0) {
		server = first_socket(&pool->used_server_list);
		if (!server)
			server = first_socket(&pool->tested_server_list);
		if (!server)
			break;
		release_disconn_pgSocket(server, SV_DISCONN, true, "too many servers in the pool");
		many--;
		cur--;
	}
}
//
///* maintain servers in a pool */
void pool_server_maint(PgPool *pool)
{
	struct List *item, *tmp;
	usec_t age, now = get_cached_time();
	PgSocket *server;

	/* find and disconnect idle servers */
	check_unused_servers(pool, &pool->used_server_list, 0);
	check_unused_servers(pool, &pool->tested_server_list, 0);
	check_unused_servers(pool, &pool->idle_server_list, 1);

	/* where query got did not get answer in query_timeout */
	if (cf_query_timeout > 0 || cf_idle_transaction_timeout > 0) {
		statlist_for_each_safe(item, &pool->active_server_list, tmp) {
			server = container_of(item, PgSocket, head);
			Assert(server->state == SV_ACTIVE);
			if (server->ready)
				continue;
			age = now - server->link->request_time;
			if (cf_query_timeout > 0 && age > cf_query_timeout) {
				release_disconn_pgSocket(server, SV_DISCONN, true, "query timeout");
			} else if (cf_idle_transaction_timeout > 0 &&
				   server->idle_tx &&
				   age > cf_idle_transaction_timeout)
			{
				release_disconn_pgSocket(server, SV_DISCONN, true, "idle transaction timeout");
			}
		}
	}

	/* find connections that got connect, but could not log in */
	if (cf_server_connect_timeout > 0) {
		statlist_for_each_safe(item, &pool->new_server_list, tmp) {
			server = container_of(item, PgSocket, head);
			Assert(server->state == SV_LOGIN);

			age = now - server->connect_time;
			if (age > cf_server_connect_timeout) {
				release_disconn_pgSocket(server, SV_DISCONN, true, "connect timeout");
			}
		}
	}

	/*handing wait test server list*/
	handing_pool_waitTestServer(pool);
}

void handing_pool_waitTestServer(PgPool *pool)
{
	PgSocket *server = NULL;
	struct List *item;
	while(statlist_count(&pool->waittest_server_list) > 0 ) {
		pthread_mutex_lock(&pool->poolMutex);
		do{
			if (statlist_count(&pool->waittest_server_list) <= 0)
				break;
			item = statlist_first(&pool->waittest_server_list);
			server = container_of(item, PgSocket, head);
			switch_thread(&server->sbuf);
			change_server_state(server, SV_TESTED);
		} while(0);
		pthread_mutex_unlock(&pool->poolMutex);

		if (!server)
			return;
		reset_server(server);
	}
}


static void kill_database(PgDatabase *db);

static void cleanup_inactive_autodatabases(void)
{
	struct List *item, *tmp;
	PgDatabase *db;
	usec_t age;
	usec_t now = get_cached_time();

	if (cf_autodb_idle_timeout <= 0)
		return;

	/* now kill the old ones */
	statlist_for_each_safe(item, &autodatabase_idle_list, tmp) {
		db = container_of(item, PgDatabase, head);
		if (db->db_paused)
			continue;
		age = now - db->inactive_time;
		if (age > cf_autodb_idle_timeout) 
			kill_database(db);
		else
			break;
	}
}

/* full-scale maintenance, done only occasionally
 * */
static void do_full_maint(int sock, short flags, void *arg)
{
	struct List *item, *tmp;
	PgDatabase *db;
	PgThread *pgThread;
	static unsigned int seq;

	seq++;
	pgThread= arg;
	Assert(pgMulThread);
	/*
	 * Avoid doing anything that may surprise other pgbouncer.
	 */
	if (cf_pause_mode == P_SUSPEND)
		goto skip_maint;

	/* find inactive autodbs */
	statlist_for_each_safe(item, &database_list, tmp) {
		db = container_of(item, PgDatabase, head);
		if (db->db_auto && db->inactive_time == 0) {
			if (db->active_stamp == seq)
				continue;
			db->inactive_time = get_cached_time();
			log_debug("xxxstatlist_remove");
			statlist_remove(&database_list, &db->head);
			statlist_append(&autodatabase_idle_list, &db->head);
		}
	}

	cleanup_inactive_autodatabases();

	if (cf_auth_type >= AUTH_TRUST)
		loader_users_check();

skip_maint:
	add_safe_evtimer(pgThread, &full_maint_ev, &full_maint_period);
}

/* first-time initializtion */
void janitor_setup(void)
{
	/* launch maintenance */
	pgbouncer_evtimer_set(pMainThread->eventBase, &full_maint_ev, do_full_maint, pMainThread);
	add_safe_evtimer(pMainThread, &full_maint_ev, &full_maint_period);
}

void kill_pool(PgPool *pool)
{
	const char *reason = "database removed";
	close_server_list(&pool->active_server_list, reason);
	close_server_list(&pool->idle_server_list, reason);
	close_server_list(&pool->used_server_list, reason);
	close_server_list(&pool->tested_server_list, reason);
	close_server_list(&pool->new_server_list, reason);

	pktbuf_free(pool->welcome_msg);

	list_del(&pool->map_head);
	statlist_remove(&pool_list, &pool->head);
	varcache_clean(&pool->orig_vars);
	slab_free_safe(pool_cache, pool);
}

static void kill_database(PgDatabase *db)
{
	PgPool *pool;
	struct List *item, *tmp;

	log_warning("dropping database '%s' as it does not exist anymore or inactive auto-database", db->name);

	statlist_for_each_safe(item, &pool_list, tmp) {
		pool = container_of(item, PgPool, head);
		if (pool->db == db)
			kill_pool(pool);
	}
	pktbuf_free(db->startup_params);
	if (db->forced_user)
		slab_free_safe(user_cache, db->forced_user);
	if (db->connect_query)
		free((void *)db->connect_query);

	if (db->inactive_time)
		statlist_remove(&autodatabase_idle_list, &db->head);
	else
		statlist_remove(&database_list, &db->head);
	slab_free_safe(db_cache, db);
}

/* as [pgbouncer] section can be loaded after databases,
   there's need for review */
void config_postprocess(void)
{
	struct List *item, *tmp;
	PgDatabase *db;

	statlist_for_each_safe(item, &database_list, tmp) {
		db = container_of(item, PgDatabase, head);
		if (db->db_dead) {
			kill_database(db);
			continue;
		}
		if (db->pool_size < 0)
			db->pool_size = cf_default_pool_size;
		if (db->res_pool_size < 0)
			db->res_pool_size = cf_res_pool_size;
	}
}

