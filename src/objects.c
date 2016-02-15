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
 * Herding objects between lists happens here.
 */

#include "bouncer.h"

/* those items will be allocated as needed, never freed */
STATLIST(user_list);
STATLIST(database_list);
STATLIST(pool_list);
struct AATree user_tree;

/*
 * client and server objects will be pre-allocated
 * they are always in either active or free lists
 * in addition to others.
 */

struct Slab *server_cache;
struct Slab *client_cache;
struct Slab *db_cache;
struct Slab *pool_cache;
struct Slab *user_cache;
struct Slab *iobuf_cache;

/*
 * libevent may still report events when event_del()
 * is called from somewhere else.  So hide just freed
 * PgSockets for one loop.
 */

/* init autodb idle list */
STATLIST(autodatabase_idle_list);

/* fast way to get number of active clients */
int get_active_client_count(void)
{
	return slab_active_count(client_cache);
}

/* fast way to get number of active servers */
int get_active_server_count(void)
{
	return slab_active_count(server_cache);
}

static void construct_client(void *obj)
{
	PgSocket *client = obj;
	memset(client, 0, sizeof(PgSocket));
	list_init(&client->head);
	sbuf_init(&client->sbuf, client_proto);
	client->state = CL_INIT;
}

static void construct_server(void *obj)
{
	PgSocket *server = obj;
	memset(server, 0, sizeof(PgSocket));
	list_init(&server->head);
	sbuf_init(&server->sbuf, server_proto);
	server->state = SV_INIT;
}

/* compare string with PgUser->name, for usage with btree */
static int user_node_cmp(uintptr_t userptr, struct AANode *node)
{

	const char *name = (const char *)userptr;
	PgUser *user = container_of(node, PgUser, tree_node);
	return strcmp(name, user->name);
}

/* initialization before config loading */
void init_objects(void)
{
	aatree_init(&user_tree, user_node_cmp, NULL);

	user_cache = slab_create("user_cache", sizeof(PgUser), 0, NULL, USUAL_ALLOC);
	db_cache = slab_create("db_cache", sizeof(PgDatabase), 0, NULL, USUAL_ALLOC);
	pool_cache = slab_create("pool_cache", sizeof(PgPool), 0, NULL, USUAL_ALLOC);

	if (!user_cache || !db_cache || !pool_cache)
		fatal("cannot create initial caches");
}

static void do_iobuf_reset(void *arg)
{
	IOBuf *io = arg;
	iobuf_reset(io);
}

/* initialization after config loading */
void init_caches(void)
{
	server_cache = slab_create("server_cache", sizeof(PgSocket), 0, construct_server, USUAL_ALLOC);
	client_cache = slab_create("client_cache", sizeof(PgSocket), 0, construct_client, USUAL_ALLOC);
	iobuf_cache = slab_create("iobuf_cache", IOBUF_SIZE, 0, do_iobuf_reset, USUAL_ALLOC);
}

void check_list_status(const char *list_name, struct StatList *list, SocketState state)
{
	struct List *item;
	PgSocket *sk;

	log_debug("list_name:%s, server list size:%d", list_name, statlist_count(list));
	statlist_for_each(item, list)
	{
		sk = container_of(item, PgSocket, head);
		log_debug("sk.state:%d, sk.index: %d\n", sk->state, sk->index);
		if (sk->state != state) {
			cause_segment();
		}
	}
}

/* state change means moving between lists */
void change_client_state(PgSocket *client, SocketState newstate)
{
	Assert(NULL != client);
	log_debug("client->stat: %d, newstate: %d, sock: %d", client->state, newstate, client->sbuf.sock);
	switch(client->state) {
		case CL_FREE:
		case CL_INIT:
		case CL_CANCEL:
			break;

		case CL_JUSTFREE:
			statlist_remove(&client->thread->justfreeList, &client->head);
			break;
		case CL_CONNECT:
			statlist_remove(&client->thread->connectList, &client->head);
			break;
		case CL_LOGIN:
			statlist_remove(&client->thread->loginList, &client->head);
			break;
		case CL_WAITING:
			statlist_remove(&client->thread->waitingList, &client->head);
			break;
		case CL_ACTIVE:
			statlist_remove(&client->thread->activeList, &client->head);
			break;
		case CL_OLDACTIVE:
			statlist_remove(&client->thread->oldActiveList, &client->head);
			break;
		case CL_DISCONN:
			statlist_remove(&client->thread->disConnectList, &client->head);
			break;
		default:
			cause_segment();
			log_error("client->state: %d, error", client->state);
		}

	client->state = newstate;

	switch(client->state) {
	case CL_CANCEL:
		break;
	case CL_FREE:
		varcache_clean(&client->vars);
		slab_free_safe(client_cache, client);
		break;

	case CL_JUSTFREE:
		statlist_append(&client->thread->justfreeList, &client->head);
		break;
	case CL_CONNECT:
		statlist_append(&client->thread->connectList, &client->head);
		break;
	case CL_LOGIN:
		statlist_append(&client->thread->loginList, &client->head);
		break;
	case CL_WAITING:
		statlist_append(&client->thread->waitingList, &client->head);
		break;
	case CL_ACTIVE:
		statlist_append(&client->thread->activeList, &client->head);
		break;
	case CL_OLDACTIVE:
		statlist_append(&client->thread->oldActiveList, &client->head);
		break;
	case CL_DISCONN:
		statlist_append(&client->thread->disConnectList, &client->head);
		break;
	default:
		cause_segment();
		log_error("client->state: %d, error", client->state);
	}
}

void change_server_state_safe(PgSocket *server, SocketState newstate)
{
	PgPool *pool = server->pool;

	Assert(pool != NULL);
	pthread_mutex_lock(&pool->poolMutex);
	change_server_state(server, newstate);
	pthread_mutex_unlock(&pool->poolMutex);
}

/* state change means moving between lists */
void change_server_state(PgSocket *server, SocketState newstate)
{
	PgPool *pool = server->pool;

	/* remove from old location */
	switch (server->state) {
	case SV_INIT:
	case SV_FREE:
		break;
	case SV_JUSTFREE:
		statlist_remove(&justfree_server_list, &server->head);
		break;
	case SV_LOGIN:
		statlist_remove(&pool->new_server_list, &server->head);
		break;
	case SV_USED:
		statlist_remove(&pool->used_server_list, &server->head);
		break;
	case SV_TESTED:
		statlist_remove(&pool->tested_server_list, &server->head);
		break;
	case SV_IDLE:
		statlist_remove(&pool->idle_server_list, &server->head);
		break;
	case SV_ACTIVE:
		statlist_remove(&pool->active_server_list, &server->head);
		break;
	case SV_OLDACTIVE:
		statlist_remove(&pool->old_active_server_list, &server->head);
		break;
	case SV_WAITING:
		statlist_remove(&pool->wait_server_list, &server->head);
		break;
	case SV_DISCONN:
		statlist_remove(&pool->disconnect_server_list, &server->head);
		break;
	case SV_WAITTEST:
		statlist_remove(&pool->waittest_server_list, &server->head);
		break;
	default:
		cause_segment();
		fatal("change_server_state: bad old server state: %d, newstate: %d", server->state, newstate);
	}

	server->state = newstate;

	/* put to new location */
	switch (server->state) {
	case SV_FREE:
		pool->serverNum -= 1;
		varcache_clean(&server->vars);
		slab_free_safe(server_cache, server);
		break;
	case SV_JUSTFREE:
		statlist_append(&justfree_server_list, &server->head);
		break;
	case SV_LOGIN:
		statlist_append(&pool->new_server_list, &server->head);
		break;
	case SV_USED:
		/* use LIFO */
		statlist_prepend(&pool->used_server_list, &server->head);
		break;
	case SV_TESTED:
		statlist_append(&pool->tested_server_list, &server->head);
		break;
	case SV_IDLE:
		if (server->close_needed || cf_server_round_robin)
			/* try to avoid immediate usage then */
			statlist_append(&pool->idle_server_list, &server->head);
		else
			/* otherwise use LIFO */
			statlist_prepend(&pool->idle_server_list, &server->head);
		break;
	case SV_ACTIVE:
		statlist_append(&pool->active_server_list, &server->head);
		break;
	case SV_OLDACTIVE:
		statlist_append(&pool->old_active_server_list, &server->head);
		break;
	case SV_WAITING:
		statlist_append(&pool->wait_server_list, &server->head);
		break;
	case SV_DISCONN:
		statlist_append(&pool->disconnect_server_list, &server->head);
		break;
	case SV_WAITTEST:
		statlist_append(&pool->waittest_server_list, &server->head);
		break;
	default:
		cause_segment();
		fatal("bad server state, newstate: %d", server->state);
	}
}
/* compare pool names, for use with put_in_order */
int cmp_pool(struct List *i1, struct List *i2)
{
	PgPool *p1 = container_of(i1, PgPool, head);
	PgPool *p2 = container_of(i2, PgPool, head);
	if (p1->db != p2->db)
		return strcmp(p1->db->name, p2->db->name);
	if (p1->user != p2->user)
		return strcmp(p1->user->name, p2->user->name);
	return 0;
}

/* compare user names, for use with put_in_order */
static int cmp_user(struct List *i1, struct List *i2)
{
	PgUser *u1 = container_of(i1, PgUser, head);
	PgUser *u2 = container_of(i2, PgUser, head);
	return strcmp(u1->name, u2->name);
}

/* compare db names, for use with put_in_order */
static int cmp_database(struct List *i1, struct List *i2)
{

	PgDatabase *db1 = container_of(i1, PgDatabase, head);
	PgDatabase *db2 = container_of(i2, PgDatabase, head);
	return strcmp(db1->name, db2->name);
}

/* put elem into list in correct pos */
void put_in_order(struct List *newitem, struct StatList *list,
			 int (*cmpfn)(struct List *, struct List *))
{

	int res;
	struct List *item;

	statlist_for_each(item, list) {
		res = cmpfn(item, newitem);
		if (res == 0)
			fatal("put_in_order: found existing elem");
		else if (res > 0) {
			statlist_put_before(list, newitem, item);
			return;
		}
	}
	statlist_append(list, newitem);
}

/* create new object if new, then return it */
PgDatabase *add_database(const char *name)
{
	PgDatabase *db = find_database(name);

	/* create new object if needed */
	if (db == NULL) {
		db = slab_alloc_safe(db_cache);
		if (!db)
			return NULL;

		list_init(&db->head);
		if (strlcpy(db->name, name, sizeof(db->name)) >= sizeof(db->name)) {
			log_warning("Too long db name: %s", name);
			slab_free_safe(db_cache, db);
			return NULL;
		}
		put_in_order(&db->head, &database_list, cmp_database);
	}

	return db;
}

/* register new auto database */
PgDatabase *register_auto_database(const char *name)
{
	PgDatabase *db;
	int len;
	char *cs;
	
	if (!cf_autodb_connstr)
		return NULL;

	len = strlen(cf_autodb_connstr);
	cs = malloc(len + 1);
	if (!cs)
		return NULL;
	memcpy(cs, cf_autodb_connstr, len + 1);
	parse_database(NULL, (char*)name, cs);
	free(cs);

	db = find_database(name);
	if (db) {
		db->db_auto = 1;
		/* do not forget to check pool_size like in config_postprocess */
		if (db->pool_size < 0)
			db->pool_size = cf_default_pool_size;
		if (db->res_pool_size < 0)
			db->res_pool_size = cf_res_pool_size;
	}

	return db;
}

/* add or update client users */
PgUser *add_user(const char *name, const char *passwd)
{
	
	PgUser *user = find_user(name);

	if (user == NULL) {
		user = slab_alloc_safe(user_cache);
		if (!user)
			return NULL;

		list_init(&user->head);
		list_init(&user->pool_list);
		safe_strcpy(user->name, name, sizeof(user->name));
		put_in_order(&user->head, &user_list, cmp_user);

		aatree_insert(&user_tree, (uintptr_t)user->name, &user->tree_node);
	}
	safe_strcpy(user->passwd, passwd, sizeof(user->passwd));
	return user;
}

/* create separate user object for storing server user info */
PgUser *force_user(PgDatabase *db, const char *name, const char *passwd)
{
	
	PgUser *user = db->forced_user;
	if (!user) {
		user = slab_alloc_safe(user_cache);
		if (!user)
			return NULL;
		list_init(&user->head);
		list_init(&user->pool_list);
	}
	safe_strcpy(user->name, name, sizeof(user->name));
	safe_strcpy(user->passwd, passwd, sizeof(user->passwd));
	db->forced_user = user;//config file user name
	return user;
}

/* find an existing database */
PgDatabase *find_database(const char *name)
{
	
	struct List *item, *tmp;
	PgDatabase *db;
	statlist_for_each(item, &database_list) {
		db = container_of(item, PgDatabase, head);
		if (strcmp(db->name, name) == 0)
			return db;
	}
	/* also trying to find in idle autodatabases list */
	statlist_for_each_safe(item, &autodatabase_idle_list, tmp) {
		db = container_of(item, PgDatabase, head);
		if (strcmp(db->name, name) == 0) {
			db->inactive_time = 0;
			statlist_remove(&autodatabase_idle_list, &db->head);
			put_in_order(&db->head, &database_list, cmp_database);
			return db;
		}
	}
	return NULL;
}

/* find existing user */
PgUser *find_user(const char *name)
{
	
	PgUser *user = NULL;
	struct AANode *node;

	node = aatree_search(&user_tree, (uintptr_t)name);
	user = node ? container_of(node, PgUser, tree_node) : NULL;
	return user;
}

/* create new pool object */
PgPool *new_pool(PgDatabase *db, PgUser *user)
{
	PgPool *pool;
	int err = 0;

	pool = slab_alloc_safe(pool_cache);
	if (!pool)
		return NULL;

	list_init(&pool->head);
	list_init(&pool->map_head);

	pool->user = user;
	pool->db = db;
	pool->serverNum = 0;

	statlist_init(&pool->active_server_list, "active_server_list");
	statlist_init(&pool->idle_server_list, "idle_server_list");
	statlist_init(&pool->tested_server_list, "tested_server_list");
	statlist_init(&pool->used_server_list, "used_server_list");
	statlist_init(&pool->new_server_list, "new_server_list");
	statlist_init(&pool->wait_server_list, "wait_server_list");
	statlist_init(&pool->cancel_server_list, "cancel_server_list");
	statlist_init(&pool->disconnect_server_list, "disconnect server list");
	statlist_init(&pool->waittest_server_list, "wait test server list");
	statlist_init(&pool->old_active_server_list, "old active server list");

	list_append(&user->pool_list, &pool->map_head);

	/* keep pools in db/user order to make stats faster */
	put_in_order(&pool->head, &pool_list, cmp_pool);

	//add by huih@20150728
	err = pthread_mutex_init(&pool->poolMutex, NULL);
	if (err < 0) {
		log_error("pthread_mutex_init error\n");
		return NULL;
	}
	err = pthread_cond_init(&pool->poolCond, NULL);
	if (err < 0) {
		log_error("pthread_cond_init error\n");
		return NULL;
	}

	return pool;
}

/* find pool object, create if needed */
PgPool *get_pool(PgDatabase *db, PgUser *user)
{
	struct List *item;
	PgPool *pool;

	if (!db || !user)
		return NULL;

	list_for_each(item, &user->pool_list) {
		pool = container_of(item, PgPool, map_head);
		if (pool->db == db) {
			return pool;
		}
	}
	return new_pool(db, user);//new a empty pool,no connect in pool
}

/* deactivate socket and put into wait queue */
static void pause_client(PgSocket *client)
{

	Assert(client->state == CL_ACTIVE);

	slog_debug(client, "pause_client");
	change_client_state(client, CL_WAITING);
	log_debug("client.index: %d, client.state: %d, sock: %d",
			client->index, client->state, client->sbuf.sock);
	if (!sbuf_pause(&client->sbuf)) {
		log_error("pause failed, client.index: %d, client.state: %d, sock: %d",
				client->index, client->state, client->sbuf.sock);
		release_disconn_pgSocket(client, CL_DISCONN, true, "pause failed");
	}
}

/* wake client from wait */
void activate_client(PgSocket *client)
{

	Assert(client->state == CL_WAITING);
	slog_debug(client, "activate_client");
	change_client_state(client, CL_ACTIVE);
	sbuf_continue(&client->sbuf);
}

void pause_server(PgSocket *server)
{
	slog_debug(server, "pause_server");
	change_server_state(server, SV_IDLE);
	log_error("server.index: %d, server.state: %d, sock: %d",
			server->index, server->state, server->sbuf.sock);
	if (!sbuf_is_pause(&server->sbuf) && !sbuf_pause(&server->sbuf)) {
		release_disconn_pgSocket(server, SV_DISCONN, true, "pause server failed");
	}
}

/* link if found, otherwise put into wait queue */
bool find_server(PgSocket *client)
{
	PgPool *pool = client->pool;
	PgSocket *server = NULL;
//	struct List *item;
	bool res = true;
//	bool varchange = false;
	bool fromClientList = true;

	Assert(client->state == CL_ACTIVE);

//	log_debug("client sock: %d", client->sbuf.sock);
	if (client->link) {
//		log_debug("client has a server, server index: %d\n", client->link->index);
		return true;
	}

	/* try to get idle server, if allowed */
	if (cf_pause_mode == P_PAUSE) {
		server = NULL;
	} else {

		//first, get server from serverlist
		if (statlist_count(&client->thread->serverList) > 0) {
			server = container_of(statlist_pop(&client->thread->serverList),
					PgSocket, client_thread_head);
			server->client_idle_time = 0;
			fromClientList = true;
		}

		if (!server) {
			server = get_server_from_pool(pool);
			fromClientList = false;
		}
	}

	if(server) {
		client->link = server;
		server->link = client;
		if (!fromClientList) {
			server->thread = client->thread;
			switch_thread(&server->sbuf);
		}
		res = true;
	} else {
		pause_client(client);
		res = false;
	}
	return res;
}

static bool life_over(PgSocket *server)
{
	PgPool *pool = server->pool;
	usec_t lifetime_kill_gap = 0;
	usec_t now = get_cached_time();
	usec_t age = now - server->connect_time;
	usec_t last_kill = now - pool->last_lifetime_disconnect;

	if (age < cf_server_lifetime)
		return false;

	if (pool->db->pool_size > 0)
		lifetime_kill_gap = cf_server_lifetime / pool->db->pool_size;

	if (last_kill >= lifetime_kill_gap)
		return true;

	return false;
}

/* connecting/active -> idle, unlink if needed */
bool release_server(PgSocket *server)
{
	PgPool *pool = server->pool;
	SocketState newstate = SV_IDLE; //SV_JUSTIDLE
	PgSocket *client = server->link;

	Assert(server->ready);

	/* remove from old list */
	switch (server->state) {
	case SV_ACTIVE:
		if (server->link != NULL) {//when test pool, server->link is NULL
			server->link->link = NULL;//delete client->link data
			server->link = NULL; //delete server->link data
		}
		if (*cf_server_reset_query) {
			/* notify reset is required */
			newstate = SV_WAITTEST;
		} else if (cf_server_check_delay == 0 && *cf_server_check_query) {
			/*
			 * deprecated: before reset_query, the check_delay = 0
			 * was used to get same effect.  This if() can be removed
			 * after couple of releases.
			 */
			newstate = SV_USED;
		}
	break;
	case SV_USED:
	case SV_TESTED:
		break;
	case SV_LOGIN:
		newstate = SV_WAITING;
		pool->last_connect_failed = 0;
		break;
	default:
		fatal("bad server state in release_server (%d)", server->state);
	}

	/* enforce lifetime immediately on release */
	if (server->state != SV_LOGIN && life_over(server)) {
		release_disconn_pgSocket(server, SV_DISCONN, true, "server_lifetime");
		pool->last_lifetime_disconnect = get_cached_time();
		return false;
	}

	/* enforce close request */
	if (server->close_needed) {
		release_disconn_pgSocket(server, SV_DISCONN, true, "close_needed");
		return false;
	}

	Assert(server->link == NULL);
//	slog_debug(server, "release_server: new state=%d", newstate);

	if (client != NULL && server->state == SV_ACTIVE && newstate == SV_IDLE) {
		server->client_idle_time = get_cached_time();
		statlist_append(&client->thread->serverList, &server->client_thread_head);
	} else {
		//add by huih@20150807, back socket to create thread
		server->thread = server->createSocketThread;
		change_server_state_safe(server, newstate);
	}
	return true;
}

/* drop server connection */
void disconnect_server(PgSocket *server, bool notify, const char *reason, ...)
{
	PgPool *pool = server->pool;
	PgSocket *client;
	static const uint8_t pkt_term[] = {'X', 0,0,0,4};//send x message, to close connect.
	int send_term = 1;
	usec_t now = get_cached_time();
	char buf[128];
	va_list ap;

	va_start(ap, reason);
	vsnprintf(buf, sizeof(buf), reason, ap);
	va_end(ap);
	reason = buf;

	if (cf_log_disconnections)
		slog_info(server, "closing because: %s (age=%" PRIu64 ")", reason,
			  (now - server->connect_time) / USEC);

	log_debug("server->state: %d, server->index: %d", server->state, server->index);
	switch (server->state) {
	case SV_ACTIVE:
		client = server->link;
		if (client) {
			client->link = NULL;
			server->link = NULL;
			release_disconn_pgSocket_unsafe(client, CL_DISCONN, true, reason);
		}
		break;
	case SV_TESTED:
	case SV_USED:
	case SV_IDLE:
	case SV_DISCONN:
		break;
	case SV_LOGIN:
		/*
		 * usually disconnect means problems in startup phase,
		 * except when sending cancel packet
		 */
		if (!server->ready)
			pool->last_connect_failed = 1;
		else
			send_term = 0;
		break;
	default:
		fatal("disconnect_server: bad server state (%d)", server->state);
	}

	Assert(server->link == NULL);

	/* notify server and close connection */
	if (send_term && notify) {
		if (!sbuf_answer(&server->sbuf, pkt_term, sizeof(pkt_term)))
			/* ignore result */
			notify = false;
	}

	if (server->dns_token) {
		adns_cancel(adns, server->dns_token);
		server->dns_token = NULL;
	}
	if (!sbuf_close(&server->sbuf))
		log_noise("sbuf_close failed, retry later");
}

/* drop client connection */
void disconnect_client(PgSocket *client, bool notify, const char *reason, ...)
{
	char buf[128];
	va_list ap;
	usec_t now = get_cached_time();
	va_start(ap, reason);
	vsnprintf(buf, sizeof(buf), reason, ap);
	va_end(ap);
	reason = buf;

	if (cf_log_disconnections) {
		slog_info(client, "closing because: %s (age=%" PRIu64 ")", reason,
			  (now - client->connect_time) / USEC);
	}

//	log_debug("client->state: %d, client index: %d\n", client->state, client->index);
	switch (client->state) {
	case CL_ACTIVE:
		if (client->link) {
			PgSocket *server = client->link;
			/* ->ready may be set before all is sent */
			if (server->ready && sbuf_is_empty(&server->sbuf)) {
				/* retval does not matter here */
				release_server(server);
			} else {
				server->link = NULL;
				client->link = NULL;
				release_disconn_pgSocket(server, SV_DISCONN, true, "unclean server");
			}
		}
		break;
	case CL_LOGIN:
	case CL_WAITING:
	case CL_CANCEL:
	case CL_DISCONN:
		break;
	default:
		fatal("bad client state in disconnect_client: %d", client->state);
	}

	/* send reason to client */
	if (notify && reason && client->state != CL_CANCEL) {
		/*
		 * don't send Ready pkt here, or client won't notice
		 * closed connection
		 */
		send_pooler_error(client, false, reason);
	}

	change_client_state(client, CL_JUSTFREE);
	if (!sbuf_close(&client->sbuf))
		log_noise("sbuf_close failed, retry later");
}

/*
 * Connection creation utilities
 */
static void connect_server(struct PgSocket *server, const struct sockaddr *sa, int salen)
{
	bool res;

	/* fill remote_addr */
	memset(&server->remote_addr, 0, sizeof(server->remote_addr));
	if (sa->sa_family == AF_UNIX) {
		pga_set(&server->remote_addr, AF_UNIX, server->pool->db->port);
	} else {
		pga_copy(&server->remote_addr, sa);
	}

	if (cf_log_connections)
		slog_info(server, "new connection to server");

	/* start connecting */
	res = sbuf_connect(&server->sbuf, sa, salen,
			   cf_server_connect_timeout / USEC);
	if (!res)
		log_noise("failed to launch new connection");
}

static void dns_callback(void *arg, const struct sockaddr *sa, int salen)
{
	struct PgSocket *server = arg;
	struct PgDatabase *db = server->pool->db;
	struct sockaddr_in sa_in;
	struct sockaddr_in6 sa_in6;

	server->dns_token = NULL;

	if (!sa) {
		release_disconn_pgSocket(server, SV_DISCONN, true, "server dns lookup failed");
		return;
	} else if (sa->sa_family == AF_INET) {//IPV4
		char buf[64];
		memcpy(&sa_in, sa, sizeof(sa_in));
		sa_in.sin_port = htons(db->port);
		sa = (struct sockaddr *)&sa_in;
		salen = sizeof(sa_in);
		slog_debug(server, "dns_callback: inet4: %s",
			   sa2str(sa, buf, sizeof(buf)));
	} else if (sa->sa_family == AF_INET6) {//IPV6
		char buf[64];
		memcpy(&sa_in6, sa, sizeof(sa_in6));
		sa_in6.sin6_port = htons(db->port);
		sa = (struct sockaddr *)&sa_in6;
		salen = sizeof(sa_in6);
		slog_debug(server, "dns_callback: inet6: %s",
			   sa2str(sa, buf, sizeof(buf)));
	} else {
		release_disconn_pgSocket(server, SV_DISCONN, true, "unknown address family: %d", sa->sa_family);
		return;
	}

	connect_server(server, sa, salen);
}

static void dns_connect(struct PgSocket *server)
{
	struct sockaddr_un sa_un;
	struct sockaddr_in sa_in;
	struct sockaddr_in6 sa_in6;
	struct sockaddr *sa;
	struct PgDatabase *db = server->pool->db;
	const char *host = db->host;
	const char *unix_dir;
	int sa_len;

	if (!host || host[0] == '/') { //unix socket
		slog_noise(server, "unix socket: %s", sa_un.sun_path);
		memset(&sa_un, 0, sizeof(sa_un));
		sa_un.sun_family = AF_UNIX;
		unix_dir = host ? host : cf_unix_socket_dir;
		if (!unix_dir || !*unix_dir) {
			log_error("Unix socket dir not configured: %s", db->name);
			release_disconn_pgSocket(server, SV_DISCONN, false, "cannot connect");
			return;
		}
		snprintf(sa_un.sun_path, sizeof(sa_un.sun_path),
			 "%s/.s.PGSQL.%d", unix_dir, db->port);
		sa = (struct sockaddr *)&sa_un;
		sa_len = sizeof(sa_un);
	} else if (strchr(host, ':')) {
		slog_noise(server, "inet6 socket: %s", db->host);
		memset(&sa_in6, 0, sizeof(sa_in6));
		sa_in6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, db->host, (void *) sa_in6.sin6_addr.s6_addr);
		sa_in6.sin6_port = htons(db->port);
		sa = (struct sockaddr *)&sa_in6;
		sa_len = sizeof(sa_in6);
	} else if (host[0] >= '0' && host[0] <= '9') { // else try IPv4
		slog_noise(server, "inet socket: %s", db->host);
		memset(&sa_in, 0, sizeof(sa_in));
		sa_in.sin_family = AF_INET;
		sa_in.sin_addr.s_addr = inet_addr(db->host);
		sa_in.sin_port = htons(db->port);
		sa = (struct sockaddr *)&sa_in;
		sa_len = sizeof(sa_in);
	} else {
		struct DNSToken *tk;
		slog_noise(server, "dns socket: %s", db->host);
		/* launch dns lookup */
		tk = adns_resolve(adns, db->host, dns_callback, server);
		if (tk)
			server->dns_token = tk;
		return;
	}

	connect_server(server, sa, sa_len);
}

/* the pool needs new connection, if possible */
void launch_new_connection(PgPool *pool)
{
	PgSocket *server;
	/* allow only small number of connection attempts at a time*/
	if (!statlist_empty(&pool->new_server_list)) {
		log_debug("launch_new_connection: already progress");
		return;
	}

	/* if server bounces, don't retry too fast*/
	if (pool->last_connect_failed) {
		usec_t now = get_cached_time();
		if (now - pool->last_connect_time < cf_server_login_retry) {
			log_error("launch_new_connection: last failed, wait");
			return;
		}
	}

	log_debug("new server, start to connect");
	/* get free conn object*/
	server = slab_alloc_safe(server_cache);
	if (!server) {
		log_error("launch_new_connection: no memory");
		return;
	}

	/* initialize it */
	server->pool = pool;
	server->pool->serverNum += 1;
	server->thread = malloc_PGCLThread(pool->thread); //new server in pool ,use main thread
	server->createSocketThread = malloc_PGCLThread(pool->thread);
	server->auth_user = server->pool->user;
	server->connect_time = get_cached_time();
	server->index = get_serverSocketIndex();
	server->is_server = 1;
	server->is_free = 0;
	server->client_idle_time = 0;
	init_varCache(&server->vars);
	pool->last_connect_time = get_cached_time();
	change_server_state(server, SV_LOGIN);//change to login state

	log_debug("start to connect server, server index: %d", server->index);
	//connect to pg
	dns_connect(server);
}

/* new client connection attempt */
PgSocket *accept_client(int sock, bool is_unix, PgCLThread* pgCLThread)
{
	PgSocket *client;

	/* get free PgSocket */
	client = slab_alloc_safe(client_cache);
	if (!client) {
		log_warning("cannot allocate client struct");
		safe_close(sock);
		return NULL;
	}

	client->connect_time = client->request_time = get_cached_time();//set request start time
	client->query_start = 0;
	client->index = get_clientSocketIndex();
	client->thread = pgCLThread;
	client->createSocketThread = pgCLThread;
	client->fd = sock;

	/* FIXME: take local and remote address from pool_accept() */
	fill_remote_addr(client, sock, is_unix);
	fill_local_addr(client, sock, is_unix);

	change_client_state(client, CL_LOGIN);

//	res = sbuf_accept(&client->sbuf, sock, is_unix);
//	if (!res) {
//		if (cf_log_connections)
//			slog_debug(client, "failed connection attempt");
//		return NULL;
//	}

	return client;
}

/* send cached parameters to client to pretend being server */
/* client managed to authenticate, send welcome msg and accept queries */
bool finish_client_login(PgSocket *client)
{
	switch (client->state) {
	case CL_LOGIN:
		change_client_state(client, CL_ACTIVE);
		break;
	case CL_ACTIVE:
		break;
	default:
		fatal("bad client state");
	}

	client->wait_for_welcome = 0;

	/* send the message */
	if (!welcome_client(client))
		return false;

	slog_debug(client, "logged in");
	log_debug("client index: %d, client sock: %d logged in", client->index, client->fd);

	return true;
}

/* client->cancel_key has requested client key */
void accept_cancel_request(PgSocket *req)
{
	Assert(req != NULL);
	//pause request
	if (!sbuf_pause(&req->sbuf)){
		log_error("sbuf_pause error");
		return;
	}
	req->state = CL_CANCEL;
	statlist_append_safe(&cancel_client_mutex, &cancel_client_list, &req->head);
}

void forward_cancel_request(PgSocket *server)
{
	bool res;
	PgSocket *req = first_socket_safe(&server->pool->poolMutex, &server->pool->cancel_server_list);

	Assert(req != NULL && req->state == CL_CANCEL);
	Assert(server->state == SV_LOGIN);

	SEND_CancelRequest(res, server, req->cancel_key);

	//remove from cancel_server_list
	statlist_remove_safe(&server->pool->poolMutex,
			&server->pool->cancel_server_list, &req->head);

	//add request to client thread disconn list.
	release_disconn_pgSocket(req, CL_DISCONN, 0, "finished cancel request");
}

bool use_client_socket(int fd, PgAddr *addr,
		       const char *dbname, const char *username,
		       uint64_t ckey, int oldfd, int linkfd,
		       const char *client_enc, const char *std_string,
		       const char *datestyle, const char *timezone,
			   PgCLThread* pgCLThread)
{
	PgSocket *client;
	PktBuf tmp;

	client = slab_alloc_safe(client_cache);
	if (!client) {
		log_warning("cannot allocate client struct");
		safe_close(fd);
		return false;
	}

	client->connect_time = client->request_time = get_cached_time();//set request start time
	client->query_start = 0;
	client->index = get_clientSocketIndex();
	client->thread = pgCLThread;
	client->createSocketThread = pgCLThread;
	client->fd = fd;
	client->suspended = 1;
	client->request_time = get_cached_time();
	client->connect_time = get_cached_time();
	client->query_start = get_cached_time();
	client->sbuf.sock = fd;
	client->is_unix = pga_is_unix(addr);
	/* store old fds */
	client->tmp_sk_oldfd = oldfd;
	client->tmp_sk_linkfd = linkfd;

	/* FIXME: take local and remote address from pool_accept() */
	fill_remote_addr(client, client->fd, client->is_unix);
	fill_local_addr(client, client->fd, client->is_unix);

	if (!set_pool(client, dbname, username)){
		release_disconn_pgSocket(client, CL_DISCONN, 1, "Set pool error, disconnect client");
		return false;
	}

	//modified by huih@20150827
	change_client_state(client, CL_OLDACTIVE);

	/* store old cancel key */
	pktbuf_static(&tmp, client->cancel_key, 8);
	pktbuf_put_uint64(&tmp, ckey);

	varcache_set(&client->vars, "client_encoding", client_enc);
	varcache_set(&client->vars, "standard_conforming_strings", std_string);
	varcache_set(&client->vars, "datestyle", datestyle);
	varcache_set(&client->vars, "timezone", timezone);

	return true;
}

bool use_server_socket(int fd, PgAddr *addr,
		       const char *dbname, const char *username,
		       uint64_t ckey, int oldfd, int linkfd,
		       const char *client_enc, const char *std_string,
		       const char *datestyle, const char *timezone, PgThread* pgThread)
{
	PgDatabase *db = find_database(dbname);
	PgUser *user;
	PgPool *pool;
	PgSocket *server;
	PktBuf tmp;
	
	/* if the database not found, it's an auto database -> registering... */
	if (!db) {
		db = register_auto_database(dbname);
		if (!db)
			return true;
	}

	if (db->forced_user)
		user = db->forced_user;
	else
		user = find_user(username);

	pool = get_pool(db, user);
	if (!pool)
		return false;
	pool->thread = pgThread;

	server = slab_alloc_safe(server_cache);
	if (!server)
		return false;

	server->suspended = 1;
	server->pool = pool;
	server->thread = malloc_PGCLThread(pool->thread);
	server->createSocketThread = malloc_PGCLThread(pool->thread);
	server->pool->serverNum += 1;
	server->auth_user = user;
	server->connect_time = server->request_time = get_cached_time();
	server->query_start = 0;
	server->index = get_serverSocketIndex();
	server->fd = fd;
	server->sbuf.sock = fd;
	server->is_unix = pga_is_unix(addr);

	//set socket
	if (!tune_socket(server->fd, server->is_unix)){
		release_disconn_pgSocket(server, SV_DISCONN, 0, "Tue socket failed. disconnect server");
		return false;
	}

	if (linkfd) {
		server->ready = 0;
		//modified by huih@20150827
		change_server_state(server, SV_OLDACTIVE);
	} else {
		server->ready = 1;
		//change_server_state(server, SV_IDLE);
		release_disconn_pgSocket(server, SV_DISCONN, 0, "Receive old idle server");
		return true;
	}

	fill_remote_addr(server, fd, pga_is_unix(addr));
	fill_local_addr(server, fd, pga_is_unix(addr));

	/* store old cancel key */
	pktbuf_static(&tmp, server->cancel_key, 8);
	pktbuf_put_uint64(&tmp, ckey);

	/* store old fds */
	server->tmp_sk_oldfd = oldfd;
	server->tmp_sk_linkfd = linkfd;

	varcache_set(&server->vars, "client_encoding", client_enc);
	varcache_set(&server->vars, "standard_conforming_strings", std_string);
	varcache_set(&server->vars, "datestyle", datestyle);
	varcache_set(&server->vars, "timezone", timezone);

	return true;
}

void for_each_server(PgPool *pool, void (*func)(PgSocket *sk))
{

	struct List *item;

	statlist_for_each(item, &pool->idle_server_list)
		func(container_of(item, PgSocket, head));

	statlist_for_each(item, &pool->used_server_list)
		func(container_of(item, PgSocket, head));

	statlist_for_each(item, &pool->tested_server_list)
		func(container_of(item, PgSocket, head));

	statlist_for_each(item, &pool->active_server_list)
		func(container_of(item, PgSocket, head));

	statlist_for_each(item, &pool->new_server_list)
		func(container_of(item, PgSocket, head));
}

static void for_each_server_filtered(PgPool *pool, void (*func)(PgSocket *sk), bool (*filter)(PgSocket *sk, void *arg), void *filter_arg)
{

	struct List *item;
	PgSocket *sk;

	statlist_for_each(item, &pool->idle_server_list) {
		sk = container_of(item, PgSocket, head);
		if (filter(sk, filter_arg))
			func(sk);
	}

	statlist_for_each(item, &pool->used_server_list) {
		sk = container_of(item, PgSocket, head);
		if (filter(sk, filter_arg))
			func(sk);
	}

	statlist_for_each(item, &pool->tested_server_list) {
		sk = container_of(item, PgSocket, head);
		if (filter(sk, filter_arg))
			func(sk);
	}

	statlist_for_each(item, &pool->active_server_list) {
		sk = container_of(item, PgSocket, head);
		if (filter(sk, filter_arg))
			func(sk);
	}

	statlist_for_each(item, &pool->new_server_list) {
		sk = container_of(item, PgSocket, head);
		if (filter(sk, filter_arg))
			func(sk);
	}
}


static void tag_dirty(PgSocket *sk)
{

	sk->close_needed = 1;
}

static void tag_pool_dirty(PgPool *pool)
{

	struct List *item, *tmp;
	struct PgSocket *server;

	/* reset welcome msg */
	if (pool->welcome_msg) {
		pktbuf_free(pool->welcome_msg);
		pool->welcome_msg = NULL;
	}
	pool->welcome_msg_ready = 0;

	/* drop all existing servers ASAP */
	for_each_server(pool, tag_dirty);

	/* drop servers login phase immediately */
	statlist_for_each_safe(item, &pool->new_server_list, tmp) {
		server = container_of(item, PgSocket, head);
		release_disconn_pgSocket(server, SV_DISCONN, true, "connect string changed");
	}
}

void tag_database_dirty(PgDatabase *db)
{

	struct List *item;
	PgPool *pool;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db == db)
			tag_pool_dirty(pool);
	}
}

void tag_autodb_dirty(void)
{

	struct List *item;
	PgPool *pool;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db->db_auto)
			tag_pool_dirty(pool);
	}
}

static bool server_remote_addr_filter(PgSocket *sk, void *arg)
{

	PgAddr *addr = arg;

	return (pga_cmp_addr(&sk->remote_addr, addr) == 0);
}

void tag_host_addr_dirty(const char *host, const struct sockaddr *sa)
{
	struct List *item;
	PgPool *pool;
	PgAddr addr;

	memset(&addr, 0, sizeof(addr));
	pga_copy(&addr, sa);

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db->host && strcmp(host, pool->db->host) == 0) {
			for_each_server_filtered(pool, tag_dirty, server_remote_addr_filter, &addr);
		}
	}
}

void release_disconn_pgSocket(PgSocket *sk,
		SocketState state, bool notify, const char *reason, ...)
{
	PgPool *pool = NULL;
	bool isServer = false;
	char buf[128];
	va_list ap;


	if (!sk) {
		log_error("sk == NULL, reason:%s", reason);
		return;
	}

	va_start(ap, reason);
	vsnprintf(buf, sizeof(buf), reason, ap);
	va_end(ap);
	reason = buf;

	isServer = is_server_socket(sk);
	if (isServer) {
		pool = sk->pool;
		pthread_mutex_lock(&pool->poolMutex);
		release_disconn_pgSocket_unsafe(sk, state, notify, reason);
		pthread_mutex_unlock(&pool->poolMutex);
	} else {
		pthread_mutex_lock(&sk->thread->thread->threadMutex);
		release_disconn_pgSocket_unsafe(sk, state, notify, reason);
		pthread_mutex_unlock(&sk->thread->thread->threadMutex);
	}
}

void release_disconn_pgSocket_unsafe(PgSocket *sk,
		SocketState state, bool notify, const char *reason, ...)
{
	char buf[128];
	va_list ap;
	bool isServer = false;

	va_start(ap, reason);
	vsnprintf(buf, sizeof(buf), reason, ap);
	va_end(ap);

//	log_debug("sk->index: %d, sk->state: %d, notify:%d, reason: %s",
//			sk->index, sk->state, notify, reason);
	if (!sbuf_is_pause(&sk->sbuf) && !sbuf_pause(&sk->sbuf)) {
		log_error("sbuf_pause fail, sock: %d", sk->sbuf.sock);
		cause_segment();
		return; //not handing now, when timeout, thread handing it.
	}

	sk->thread = sk->createSocketThread;
	sk->disconn_notify = notify;
	sk->is_free = 1;
	sk->disconn_reason = (char *)malloc(strlen(buf) +1);
	if (sk->disconn_reason != NULL) {
		memcpy(sk->disconn_reason, buf, strlen(buf));
	}

	//back to create thread
	isServer = is_server_socket(sk);
	if (isServer) {
		change_server_state(sk, state);
	} else {
		change_client_state(sk, state);
	}
}
void reset_server(PgSocket *server)
{
	bool res = false;

	Assert(server->state == SV_TESTED);
	slog_debug(server, "Resetting: %s", cf_server_reset_query);
	SEND_generic(res, server, 'Q', "s", cf_server_reset_query);
	if (!res)
		release_disconn_pgSocket(server, SV_DISCONN, false, "reset query failed");
}

//
PgOldSocket* get_oldPgSocket(int fd, PgAddr *addr,
	       const char *dbname, const char *username,
	       uint64_t ckey, int oldfd, int linkfd,
	       const char *client_enc, const char *std_string,
	       const char *datestyle, const char *timezone, bool is_pooler)
{
	PgOldSocket *serverSocket = NULL;

	serverSocket = (PgOldSocket*)malloc(sizeof(PgOldSocket));
	if (!serverSocket) {
		fatal_perror("no memory, malloc PgOldSocket error");
		return serverSocket;
	}

	serverSocket->fd = fd;
	serverSocket->addr = *addr;

	if (is_pooler) {
		return serverSocket;
	}

	serverSocket->ckey = ckey;
	serverSocket->oldfd = oldfd;
	serverSocket->linkfd = linkfd;

	if (NULL != dbname) {
		memcpy(serverSocket->dbName, dbname,
			strlen(dbname) < MAX_DBNAME ? strlen(dbname) : MAX_DBNAME);
	}

	if (NULL != username) {
		memcpy(serverSocket->userName, username,
			strlen(username) < MAX_USERNAME ? strlen(username) : MAX_USERNAME);
	}

	if (NULL != client_enc) {
		memcpy(serverSocket->client_enc, client_enc,
			strlen(client_enc) < MAX_PGPARAM ? strlen(client_enc) : MAX_PGPARAM);
	}

	if (NULL != std_string) {
		memcpy(serverSocket->std_string, std_string,
				strlen(std_string) < MAX_PGPARAM ? strlen(std_string) : MAX_PGPARAM);
	}

	if (NULL != datestyle){
		memcpy(serverSocket->datestyle, datestyle,
				strlen(datestyle) < MAX_PGPARAM ? strlen(datestyle) : MAX_PGPARAM);
	}

	if (NULL != timezone) {
		memcpy(serverSocket->timezone, timezone,
				strlen(timezone) < MAX_PGPARAM ? strlen(timezone) : MAX_PGPARAM);
	}
	return serverSocket;
}
