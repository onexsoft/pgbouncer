/*
 * testserverpool.c
 *
 *  Created on: 201589
 *      Author: hui
 */
#include<bouncer.h>
#include "testserverpool.h"

static struct timeval serverPool_monitor_period = {600, 0};
static struct event serverPool_monitor_ev;
void do_serverPool_monitor(int sock, short flags, void *arg);

static struct timeval client_monitor_period = {600, 0};
void do_clientThread_monitor(int sock, short flags, void *arg);

void serverPool_monitor(PgThread* pgThread)
{
	Assert(pgMulThread != NULL);
	pgbouncer_evtimer_set(pgThread->eventBase,
			&serverPool_monitor_ev,
			do_serverPool_monitor, pgThread);

	add_safe_evtimer(pgThread, &serverPool_monitor_ev,
			&serverPool_monitor_period);
}
void do_serverPool_monitor(int sock, short flags, void *arg)
{
	PgThread *pgThread = arg;
	serverPool_print();

	add_safe_evtimer(pgThread, &serverPool_monitor_ev,
				&serverPool_monitor_period);
}

void clientThread_monitor(PgCLThread* pgCLThread)
{
	Assert(pgCLThread != NULL);
	pgbouncer_evtimer_set(pgCLThread->thread->eventBase,
			&pgCLThread->monitor_evt,
			do_clientThread_monitor, pgCLThread);

	add_safe_evtimer(pgCLThread->thread, &pgCLThread->monitor_evt, &client_monitor_period);
}

void do_clientThread_monitor(int sock, short flags, void *arg)
{
	PgCLThread *pgCLThread = arg;
	log_error("thread_index: %d, activeSZ: %d, connectSZ: %d, "
						"disconnSZ: %d, justfreeSZ: %d, loginSZ: %d,"
						"waitingSZ: %d, serverSZ:%d, oldActiveSZ: %d",
						pgCLThread->thread->threadIndex,
						statlist_count(&pgCLThread->activeList),
						statlist_count(&pgCLThread->connectList),
						statlist_count(&pgCLThread->disConnectList),
						statlist_count(&pgCLThread->justfreeList),
						statlist_count(&pgCLThread->loginList),
						statlist_count(&pgCLThread->waitingList),
						statlist_count(&pgCLThread->serverList),
						statlist_count(&pgCLThread->oldActiveList));

	add_safe_evtimer(pgCLThread->thread, &pgCLThread->monitor_evt, &client_monitor_period);
}


void serverPool_print(void)
{
	struct List *item;
	PgPool *pPgPool;

	statlist_for_each(item, &pool_list) {
		pPgPool = container_of(item, PgPool, head);
		if (pPgPool->db->admin){
			continue;
		}
		log_error("poolname: %s, dbName: %s, servernum:%d, activeserverList: %d, cancelserverlist: %d, "
				"disconnectserverlist: %d, idleserverlist: %d, newserverlist: %d, "
				"testedserverlist: %d, usedserverlist: %d, "
				"waitserverlist:%d, waittestlist: %d, oldActiveList: %d",
				pPgPool->db->name, pPgPool->db->dbname, pPgPool->serverNum,
				statlist_count(&pPgPool->active_server_list),
				statlist_count(&pPgPool->cancel_server_list),
				statlist_count(&pPgPool->disconnect_server_list),
				statlist_count(&pPgPool->idle_server_list),
				statlist_count(&pPgPool->new_server_list),
				statlist_count(&pPgPool->tested_server_list),
				statlist_count(&pPgPool->used_server_list),
				statlist_count(&pPgPool->wait_server_list),
				statlist_count(&pPgPool->waittest_server_list),
				statlist_count(&pPgPool->old_active_server_list));
	}
}

void serverPool_new_pool(void)
{
	PgDatabase *db;
	PgUser *user;
	PgPool *pool;
	int err = 0;

	db = find_database("f_bench");
	user = find_user("harris");
	memcpy(user->name, "db_user", 8);
	if (!db || !user) {
		log_error("db == NULL || user == NULL");
		return;
	}

	pool = slab_alloc(pool_cache);
	if (!pool)
		return;

	list_init(&pool->head);
	list_init(&pool->map_head);

	pool->user = user;
	pool->db = db;

	statlist_init(&pool->active_server_list, "active_server_list");
	statlist_init(&pool->idle_server_list, "idle_server_list");
	statlist_init(&pool->tested_server_list, "tested_server_list");
	statlist_init(&pool->used_server_list, "used_server_list");
	statlist_init(&pool->new_server_list, "new_server_list");
	statlist_init(&pool->wait_server_list, "wait_server_list");
	statlist_init(&pool->cancel_server_list, "cancel_server_list");
	statlist_init(&pool->disconnect_server_list, "disconnect server list");
//	statlist_init(&pool->justidle_server_list, "just idle server list");

	/* keep pools in db/user order to make stats faster */
	statlist_append(&pool_list, &pool->head);

	//add by huih@20150728
	err = pthread_mutex_init(&pool->poolMutex, NULL);
	if (err < 0) {
		log_error("pthread_mutex_init error\n");
		return ;
	}
	err = pthread_cond_init(&pool->poolCond, NULL);
	if (err < 0) {
		log_error("pthread_cond_init error\n");
		return ;
	}
	return;
}

void print_event_log(int severity, const char *msg)
{
	log_error("event msg:%s", msg);
}

