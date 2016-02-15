/*
 * multhreads.c
 *
 *  Created on: 2015723
 *      Author: April
 */
#include "bouncer.h"

STATLIST(clientThread_list);//add by huih@20150723
STATLIST(cancel_client_list);

STATLIST(oldClientSocket_list); //add by huih@20150826
static int oldClientSocketNum = 0; //record the number of oldclientsocket list

pthread_mutex_t cancel_client_mutex;
pthread_mutex_t old_clientSocket_mutex;

static struct timeval clientThread_maint_period = {0, USEC/3};

static PgCLThread* new_clientThread(const char *name, const int nthreads);
static void * worker_thread(void* arg);
//assign task to other multhread
static void handing_connect_socket(PgCLThread* pgCLThread);
//generate current thread index
static int get_clientThreadIndex(void);
//cal the number of multhread list client
static int sum_threadList(PgCLThread* pgCLThread);
static bool empty_threadList(PgCLThread* pgCLThread);

//multhread accept connect
static PgSocket *accept_client_socket(PgCLThread* pgCLThread, PgSocket* clientSocket);
//recycle client_cache
static void recycle_client_socket(PgCLThread *pgCLThread);
//cancel client 
static void cancel_client_request(PgCLThread *pgCLThread);
static void maint_global_control(PgCLThread *pgCLThread);
static void cleanup_client_logins(PgCLThread *pgCLThread);
static void free_client_socketlist(struct StatList* list);
static void disconnect_client_socket(PgCLThread *pgCLThread);

//static void maint_clientThread_socket(PgCLThread *pgCLThread);
static void maint_client_socket(PgCLThread *pgCLThread);

static void setup_clientThread_janitor(PgCLThread *pgCLThread);
void do_clientThread_maint(int sock, short flags, void *arg);

static void check_currentIdleServer(PgCLThread *pgCLThread);
//add by huih@20150826,handle old socket
static int handle_oldClientSocket(PgCLThread *pgCLThread);
//add by huih@20150826, link old client socket
static void link_oldClientSocket(PgCLThread *pgCLThread);
//add by huih@20150827, check active client, when timeout, disconnect
static void check_oldClientSocketTimeout(PgCLThread *pgCLThread);

int init_clientThread(void)
{
	int i = 0;
	int err = 0;
	PgCLThread *pgCLThread = NULL;

	err = pthread_mutex_init(&cancel_client_mutex, NULL);
	if (err < 0){
		log_error("init cancel client mutex error\n");
		return -1;
	}

	//add by huih@20150826
	err = pthread_mutex_init(&old_clientSocket_mutex, NULL);
	if (err < 0){
		log_error("init old client socket mutex error\n");
		return -1;
	}

	cf_threads_num <= 0 ? cf_threads_num = 1 : cf_threads_num;
	for (i = 0; i < cf_threads_num; ++i)
	{
		//init
		pgCLThread = new_clientThread("client threads", cf_threads_num);
		if (pgCLThread == NULL)
		{
			log_error("malloc PgMulThread error\n");
			return -1;
		}
		err = pthread_create(&pgCLThread->thread->tid, NULL, worker_thread, pgCLThread);
		if (err < 0) {
			log_error("pthread_create error, threads_num: %d, current_index: %d, "
					"errno: %d, errstr: %s\n", cf_threads_num, i, errno, strerror(errno));
			return -1;
		}
		statlist_append(&clientThread_list, &pgCLThread->head);
	}
	return 0;
}

static void * worker_thread(void* arg)
{
	PgCLThread *pgCLThread = NULL;
	int err = -1;

	pgCLThread = arg;
	Assert(pgCLThread != NULL);

	setup_clientThread_janitor(pgCLThread);

	//add monitor
	clientThread_monitor(pgCLThread);

	//handle old client socket
	handle_oldClientSocket(pgCLThread);

	while (cf_shutdown < 2) {
		err = event_base_loop(pgCLThread->thread->eventBase, EVLOOP_ONCE);// | EVLOOP_NONBLOCK
		if (err < 0) {
			log_error("event_base_loop error, thread id: %u, current_thread_index: %d, errno: %d, errstr: %s\n",
					(unsigned int)pgCLThread->thread->tid, pgCLThread->current_thread_index, errno, strerror(errno));
			return (void*)-1;
		}

		//handing wait connect list
		handing_connect_socket(pgCLThread);

		//handing recycle socket
		recycle_client_socket(pgCLThread);

		//timing event
		run_timerEvent(pgCLThread->thread);

		disconnect_client_socket(pgCLThread);

		check_currentIdleServer(pgCLThread);
	}
	return (void*)0;
}

int handle_client_use_clientThread(int fd, bool is_unix)
{
	struct List *item;
	PgCLThread *pgCLThread, *minCLthread;
	int minClient = -1, iSumlist, res = 0;
	PgSocket *pPgSocket;

	do {
		pPgSocket = slab_alloc_safe(client_cache);
		if (pPgSocket == NULL)
		{
			log_error("malloc PgClientConnect error\n");
			res = -1;
			break;
		}

		pPgSocket->fd = fd;
		pPgSocket->is_unix = is_unix;
		pPgSocket->connect_time = get_cached_time();
		pPgSocket->request_time = 0;
		pPgSocket->query_start = 0;
		pPgSocket->is_server = 0;
		pPgSocket->is_free = 0;
		pPgSocket->disconn_reason = NULL;
		init_varCache(&pPgSocket->vars);
		pPgSocket->index = get_clientSocketIndex();
		pPgSocket->is_block = socket_set_nonblocking(fd, 1) ? 0 : 1;
		pPgSocket->state = CL_INIT;
		{
			minCLthread = NULL;
			//find the multhread that have min clients
			statlist_for_each(item, &clientThread_list) {
				pgCLThread = container_of(item, PgCLThread, head);
				iSumlist = sum_threadList(pgCLThread);
				if (minCLthread == NULL || iSumlist < minClient) {
					minClient = iSumlist;
					minCLthread = pgCLThread;
				}
			}

			if (minCLthread == NULL) {
				log_error("find min multhread error or current all multhread list is full\n");
				res = -1;
				break;
			}
			pPgSocket->thread = minCLthread;
			pPgSocket->createSocketThread = minCLthread;

			pthread_mutex_lock(&minCLthread->thread->threadMutex);
			change_client_state(pPgSocket, CL_CONNECT);
			pthread_cond_signal(&minCLthread->thread->threadCond);
			pthread_mutex_unlock(&minCLthread->thread->threadMutex);
		}
	} while(0);

	return res;
}

static void handing_connect_socket(PgCLThread* pgCLThread)
{
	struct List *item;
	PgSocket *client;
	
	Assert(pgCLThread != NULL);

	if (empty_threadList(pgCLThread)) {
		pthread_mutex_lock(&pgCLThread->thread->threadMutex);
		while(empty_threadList(pgCLThread) && cf_shutdown < 2) {
			log_error("xxx pthread_cond_waint xxx");
			pthread_cond_wait(&pgCLThread->thread->threadCond, &pgCLThread->thread->threadMutex);
		}
		pthread_mutex_unlock(&pgCLThread->thread->threadMutex);
	}

	statlist_for_each(item, &pgCLThread->waitingList) {
		client = container_of(item, PgSocket, head);
		Assert(client->pool != NULL);

		if (client->suspended)
			continue;

		if (statlist_count(&pgCLThread->serverList)
				|| statlist_count(&client->pool->idle_server_list)) {
			activate_client(client);
			return;
		}
	}

	if (statlist_count(&pgCLThread->connectList) <= 0) {
		return;
	}

	item = statlist_first(&pgCLThread->connectList);
	client = container_of(item, PgSocket, head);
	client = accept_client_socket(pgCLThread, client);
}

static void recycle_client_socket(PgCLThread *pgCLThread)
{
	struct List *item, *tmp;
	PgSocket *client;
	bool close_works = true;

	Assert(pgCLThread != NULL);
	statlist_for_each_safe(item, &pgCLThread->justfreeList, tmp) {
		client = container_of(item, PgSocket, head);
		if (sbuf_is_closed(&client->sbuf)) {
			change_client_state(client, CL_FREE);
		}
		else if (close_works)
			close_works = sbuf_close(&client->sbuf);
	}
}

static int sum_threadList(PgCLThread* pgCLThread)
{
	Assert(pgCLThread);
	return statlist_count(&pgCLThread->connectList)
			+ statlist_count(&pgCLThread->activeList)
			+ statlist_count(&pgCLThread->justfreeList)
			+ statlist_count(&pgCLThread->waitingList)
			+ statlist_count(&pgCLThread->loginList)
			+ statlist_count(&pgCLThread->disConnectList)
			+ statlist_count(&pgCLThread->oldActiveList);
}
static bool empty_threadList(PgCLThread* pgCLThread)
{
	Assert(pgCLThread);

	return (statlist_count(&pgCLThread->connectList)
				|| statlist_count(&pgCLThread->activeList)
				|| statlist_count(&pgCLThread->justfreeList)
				|| statlist_count(&pgCLThread->waitingList)
				|| statlist_count(&pgCLThread->loginList)
				|| statlist_count(&pgCLThread->disConnectList)
				|| statlist_count(&pgCLThread->serverList)
				|| statlist_count(&pgCLThread->oldActiveList)) == 0;
}


static PgSocket *accept_client_socket(PgCLThread* pgCLThread, PgSocket* client)
{
	bool res;

	Assert(client != NULL);
	Assert(pgCLThread != NULL);

	client->thread = pgCLThread;
	client->createSocketThread = pgCLThread;
	client->request_time = get_cached_time();//set request time
	client->query_start = 0;

	/* FIXME: take local and remote address from pool_accept() */
	fill_remote_addr(client, client->fd, client->is_unix);
	fill_local_addr(client, client->fd, client->is_unix);

	change_client_state(client, CL_LOGIN);//set client to CL_LOGIN state

	res = sbuf_accept(&client->sbuf, client->fd, client->is_unix);
	if (!res) {
		if (cf_log_connections)
			slog_debug(client, "failed connection attempt");
		return NULL;
	}
	return client;
}

static PgCLThread* new_clientThread(const char *name, const int nthreads)
{
	PgCLThread *pgCLThread = NULL;
	int currentThreadIndex = get_clientThreadIndex();

	Assert(name != NULL);
	//init
	pgCLThread = (PgCLThread*)malloc(sizeof(PgCLThread));
	if (pgCLThread == NULL)
	{
		log_error("malloc PgMulThread error\n");
		return pgCLThread;
	}

	{
		pgCLThread->current_thread_index = currentThreadIndex;
		pgCLThread->thread_num = nthreads;
		pgCLThread->thread = new_pgThread(name);
		if (NULL == pgCLThread->thread) {
			log_error("NULL == pgCLThread->thread");
			free(pgCLThread);
			return NULL;
		}
		statlist_init(&pgCLThread->connectList, "client thread need to handle connect list");
		statlist_init(&pgCLThread->loginList, "client thread is login list");
		statlist_init(&pgCLThread->activeList, "client thread active list");
		statlist_init(&pgCLThread->justfreeList,"client thread just free list");
		statlist_init(&pgCLThread->waitingList, "client thread waiting list");
		statlist_init(&pgCLThread->disConnectList, "client thread disconnect list");
		statlist_init(&pgCLThread->serverList, "client thread ask server list");
		statlist_init(&pgCLThread->oldActiveList, "client old active list");
	}
	return pgCLThread;
}

static void cancel_client_request(PgCLThread *pgCLThread)
{
	struct List *item, *citem;
	bool res;
	int ret;
	PgSocket *client, *cclient, *server, *mainClient;
	
	Assert(pgCLThread != NULL);

	//no handingList,no need to cancel client
	if (statlist_count(&pgCLThread->activeList) <= 0
			|| statlist_count(&cancel_client_list) <= 0) {
		return;
	}
	
	ret = pthread_mutex_trylock(&cancel_client_mutex);
	log_error("pthread_mutex_trylock");
	if (ret < 0) {//current have thread own the lock, no handing the cancel client now.
		return;
	}
	statlist_for_each(item, &pgCLThread->activeList){
		client = container_of(item, PgSocket, head);
		mainClient = NULL;
		statlist_for_each(citem, &cancel_client_list){
			cclient = container_of(item, PgSocket, head); //cancel client
			if (memcmp(client->cancel_key, cclient->cancel_key, 8) == 0){
				mainClient = cclient;
				do{
					if (NULL == client->link){ //no server
						if (client->pool->db->admin) {
							release_disconn_pgSocket(cclient, CL_DISCONN, false, "cancel request for console client");
							admin_handle_cancel(client);
							break;
						}
						release_disconn_pgSocket(cclient, CL_DISCONN, false, "cancel request for idle client");
						SEND_ReadyForQuery(res, client);
						if (!res){
							release_disconn_pgSocket(client, CL_DISCONN, true, "ReadyForQuery for main_client failed");
						}
					} else {//has server
						if (!sbuf_close(&cclient->sbuf)) {
							log_noise("sbuf_close failed, retry later");
						}
						server = client->link;
						memcpy(cclient->cancel_key, server->cancel_key, 8);//copy server cancel_key to cacel client
						cclient->pool = client->pool;
					}
				} while(0);
				break;
			}
		}

		if (NULL != mainClient) {//find,delete from cancel_client_list
			statlist_remove(&cancel_client_list, &mainClient->head);
		}
		if (NULL != mainClient && NULL != mainClient->link) {//has server
			statlist_append_safe(&mainClient->pool->poolMutex,
					&mainClient->pool->cancel_server_list, &mainClient->head);
		}
	}
	pthread_mutex_unlock(&cancel_client_mutex);
}

static void maint_global_control(PgCLThread *pgCLThread)
{
	int active = 0;
	bool force_suspend = false;

	Assert(pgCLThread != NULL);
	if (cf_pause_mode == P_SUSPEND && cf_suspend_timeout > 0) {
		usec_t stime = get_cached_time() - g_suspend_start;
		if (stime >= cf_suspend_timeout){
			force_suspend = true;
		}
	}

	switch (cf_pause_mode) {
	case P_SUSPEND:
		active += suspend_socket_list(&pgCLThread->activeList, force_suspend);
		active += suspend_socket_list(&pgCLThread->waitingList, force_suspend);

		if (force_suspend){
			suspend_socket_list(&pgCLThread->connectList, true);
			suspend_socket_list(&pgCLThread->loginList, true);
		} else {
			active += statlist_count(&pgCLThread->connectList);
			active += statlist_count(&pgCLThread->loginList);
		}

		log_debug("active: %d, force_suspend: %d", active, force_suspend);
		if (!active) {
			admin_pause_done(pgCLThread);
		}

		break;
	case P_PAUSE:
		close_client_list(&pgCLThread->connectList, "application pause");
		close_client_list(&pgCLThread->loginList, "application pause");
		active += statlist_count(&pgCLThread->activeList);
		active += statlist_count(&pgCLThread->waitingList);
		active += statlist_count(&pgCLThread->oldActiveList);
		if (!active)
			admin_pause_done(pgCLThread);
		break;
	case P_NONE:
		resume_socket_list(&pgCLThread->activeList);
		resume_socket_list(&pgCLThread->waitingList);
		break;
	}
}

static void maint_client_socket(PgCLThread *pgCLThread)
{
	struct List *item, *tmp;
	usec_t now = get_cached_time();
	PgSocket *client;
	usec_t age;

	Assert(pgCLThread != NULL);
	/* force client_idle_timeout */
	if (cf_client_idle_timeout > 0) {
		close_reqtimeout_client_list(&pgCLThread->activeList, "client_idle_timeout");
		close_reqtimeout_client_list(&pgCLThread->connectList, "client_idle_timeout");
	}

	/* force timeouts for waiting queries */
	if (cf_query_timeout > 0 || cf_query_wait_timeout > 0) {
		statlist_for_each_safe(item, &pgCLThread->waitingList, tmp) {
			client = container_of(item, PgSocket, head);
			Assert(client->state == CL_WAITING);
			if (client->query_start == 0) {
				age = now - client->request_time;
			} else
				age = now - client->query_start;

			if (cf_query_timeout > 0 && age > cf_query_timeout) {
				release_disconn_pgSocket(client, CL_DISCONN, true, "query_timeout");
			} else if (cf_query_wait_timeout > 0 && age > cf_query_wait_timeout){
				release_disconn_pgSocket(client, CL_DISCONN, true, "query_wait_timeout");
			}
		}
	}

	/* apply client_login_timeout to clients waiting for welcome pkt */
	statlist_for_each_safe(item, &pgCLThread->loginList, tmp) {
		client = container_of(item, PgSocket, head);
		if (cf_client_login_timeout > 0) {
			if (!client->wait_for_welcome)
				continue;
			age = now - client->connect_time;
			if (age > cf_client_login_timeout) {
				release_disconn_pgSocket(client, CL_DISCONN, true, "client login timeout (server down)");
			}
		}
	}
}

static void cleanup_client_logins(PgCLThread *pgCLThread)
{
	struct List *item, *tmp;
	PgSocket *client;
	usec_t age;
	usec_t now = 0;

	Assert(pgCLThread != NULL);

	if (cf_client_login_timeout <= 0)
		return;

	now = get_cached_time();
	statlist_for_each_safe(item, &pgCLThread->connectList, tmp) {
		client = container_of(item, PgSocket, head);
		age = now - client->connect_time;
		if (age > cf_client_login_timeout) {
			log_error("client->connect_time: %"PRIu64", now: %"PRIu64", age: %"PRIu64
										", cf_client_login_timeout: %"PRIu64,
										client->connect_time, now, age, cf_client_login_timeout);
			release_disconn_pgSocket(client, CL_DISCONN, true, "client_login_timeout");
		}
	}
}

static void free_client_socketlist(struct StatList* list)
{
	struct List *item, *tmp;
	PgSocket *client;

	//when shutdown, close socket immediately.
	statlist_for_each_safe(item, list, tmp){
		client = container_of(item, PgSocket, head);
		if(!sbuf_close(&client->sbuf)) {
			log_error("close client socket fail.");
		}
	}
}

void destroy_clientThread(void)
{
	struct List *item;
	PgCLThread *pgCLThread;

	while(statlist_count(&clientThread_list) > 0) {
		item = statlist_pop(&clientThread_list);
		pgCLThread = container_of(item, PgCLThread, head);

		//when shutdown, pause mode is suspend.user use -R parameter restart application
		if (cf_pause_mode != P_SUSPEND){
			free_client_socketlist(&pgCLThread->activeList);
			free_client_socketlist(&pgCLThread->waitingList);
			free_client_socketlist(&pgCLThread->oldActiveList);
		}
		free_client_socketlist(&pgCLThread->loginList);
		free_client_socketlist(&pgCLThread->connectList);

		//wait thread stop
		pthread_join(pgCLThread->thread->tid, NULL);
		destroy_pgThread(pgCLThread->thread);

		//free thread used resource
		if (pgCLThread != NULL) {
			free(pgCLThread);
			pgCLThread = NULL;
		}
	}
}

static int get_clientThreadIndex(void)
{
	static int index = 0;
	return index++;
}

static void disconnect_client_socket(PgCLThread *pgCLThread)
{
	PgSocket *client;

	while(statlist_count(&pgCLThread->disConnectList) > 0) {
		client = first_socket(&pgCLThread->disConnectList);
		disconnect_client(client, client->disconn_notify, "%s", client->disconn_reason);
		if (client->disconn_reason) {
			free(client->disconn_reason);
			client->disconn_reason = NULL;
		}
	}
}

PgCLThread* malloc_PGCLThread(PgThread* pgThread)
{
	PgCLThread *pgCLThread = NULL;
	pgCLThread = (PgCLThread*)malloc(sizeof(PgCLThread));
	if (pgCLThread == NULL) {
		return NULL;
	}
	pgCLThread->thread = pgThread;
	return pgCLThread;
}

static void setup_clientThread_janitor(PgCLThread *pgCLThread)
{
	Assert(pgCLThread != NULL);
	pgbouncer_evtimer_set(pgCLThread->thread->eventBase,
			&pgCLThread->timer_evt,
			do_clientThread_maint, pgCLThread);

	add_safe_evtimer(pgCLThread->thread, &pgCLThread->timer_evt, &clientThread_maint_period);
}

void do_clientThread_maint(int sock, short flags, void *arg)
{
	PgCLThread *pgCLThread = arg;

	//handing cancel request
	cancel_client_request(pgCLThread);

	maint_global_control(pgCLThread);

	maint_client_socket(pgCLThread);

	cleanup_client_logins(pgCLThread);

	link_oldClientSocket(pgCLThread);

	check_oldClientSocketTimeout(pgCLThread);

	add_safe_evtimer(pgCLThread->thread, &pgCLThread->timer_evt, &clientThread_maint_period);
}

static void check_currentIdleServer(PgCLThread *pgCLThread)
{
	struct List *item, *tmp;
	PgSocket *server;
	usec_t now;

	now = get_cached_time();
	statlist_for_each_safe(item, &pgCLThread->serverList, tmp) {
		server = container_of(item, PgSocket, client_thread_head);
		if (now - server->client_idle_time > cf_client_server_idle_timeout) {
			statlist_remove(&pgCLThread->serverList, &server->client_thread_head);
			server->thread = server->createSocketThread;
			change_server_state_safe(server, SV_IDLE);
		}
	}
}

void add_clientOldSocket(PgOldSocket* pgOldSocket)
{
	statlist_append(&oldClientSocket_list, &pgOldSocket->head);
	oldClientSocketNum = statlist_count(&oldClientSocket_list);
}

static int handle_oldClientSocket(PgCLThread *pgCLThread)
{
	PgOldSocket *pgOldSocket = NULL;
	bool err = false;
	int cnt = 0;

	pthread_mutex_lock(&old_clientSocket_mutex);
	cnt = (oldClientSocketNum + cf_threads_num - 1) / cf_threads_num;
	while (statlist_count(&oldClientSocket_list) > 0 && (cnt -- > 0)) {
		pgOldSocket = container_of(statlist_pop(&oldClientSocket_list),
				PgOldSocket, head);

		err = use_client_socket(pgOldSocket->fd, &pgOldSocket->addr,
				pgOldSocket->dbName, pgOldSocket->userName, pgOldSocket->ckey,
				pgOldSocket->oldfd, pgOldSocket->linkfd,
				pgOldSocket->client_enc, pgOldSocket->std_string,
				pgOldSocket->datestyle, pgOldSocket->timezone, pgCLThread);
		if (!err) {
			pthread_mutex_unlock(&old_clientSocket_mutex);
			return -1;
		}
	}
	pthread_mutex_unlock(&old_clientSocket_mutex);

	return 0;
}

static void link_oldClientSocket(PgCLThread *pgCLThread)
{
	struct List *item, *tmp;
	PgSocket *client;

	if (statlist_count(&pgCLThread->oldActiveList) <= 0)
		return;

	statlist_for_each_safe(item, &pgCLThread->oldActiveList, tmp) {
		client = container_of(item, PgSocket, head);
		if (client->old_linkFd == 0) {
			change_client_state(client, CL_WAITING);
		} else if(!link_client_server(client)) {
			slog_debug(client, "No link server now");
		}
	}
}

static void check_oldClientSocketTimeout(PgCLThread *pgCLThread)
{
	struct List *item, *tmp;
	PgSocket *client;
	usec_t now;

	if (statlist_count(&pgCLThread->oldActiveList) <= 0)
		return;

	now = get_cached_time();
	statlist_for_each_safe(item, &pgCLThread->oldActiveList, tmp) {
		client = container_of(item, PgSocket, head);

		if (now - client->request_time > cf_oldBouncer_socket_link_timeout) {
			log_error("now: %" PRIu64 ", request_time: %" PRIu64 ", "
								"cf_server_idle_timeout: %" PRIu64 "\n",now,
								client->request_time, cf_oldBouncer_socket_link_timeout);
			release_disconn_pgSocket(client, CL_DISCONN, 1, "old bouncer timeout not link server");
		}
	}
}

void shutdown_clientThread(void)
{
	struct List *item;
	PgCLThread *pgCLThread;

	statlist_for_each(item, &clientThread_list) {
		pgCLThread = container_of(item, PgCLThread, head);
		shutdown_pgThread(pgCLThread->thread);
	}
}
