/*
 * acceptthread.h
 *
 *  Created on: 20150808
 *      Author: hui
 */
#include "bouncer.h"

static PgThread *acceptThread;
STATLIST(oldPooler_list);//add by huih@20150826
static struct timeval acceptThread_period = {0, USEC/3};
static struct event acceptThread_ev;

static void* start_work(void *arg);
static void maintain_pooler(PgThread *pgMulThread);

static void setup_acceptThread_janitor(PgThread *pgThread);
static void do_acceptThread_maint(int sock, short flags, void *arg);

int init_acceptThread(void)
{
	int err;
	acceptThread = new_pgThread("accept thread");
	if (acceptThread == NULL) {
		log_error("init acceptThread fail");
		return -1;
	}

	err = pthread_create(&acceptThread->tid, NULL, start_work ,acceptThread);
	if (err) {
		log_error("create thread error\n");
		return -1;
	}
	return 0;
}

void destory_acceptThread(void)
{
	PgOldSocket *pgOldSocket;
	pthread_join(acceptThread->tid, NULL);
	destroy_pgThread(acceptThread);

	//free oldPooler_list
	while(statlist_count(&oldPooler_list) > 0) {
		pgOldSocket = container_of(statlist_pop(&oldPooler_list), PgOldSocket, head);
		if (pgOldSocket)
			free(pgOldSocket);
	}
}

static void* start_work(void *arg)
{
	int err = 0;
	PgThread *pgThread;
	struct List *item;
	PgOldSocket *pgOldSocket;

	pgThread = arg;
	Assert(pgMulThread != NULL);

	//when oldPooler_list size > 0, current start use -R parameter
	if (statlist_count(&oldPooler_list) > 0) {
		while(statlist_count(&oldPooler_list) > 0) {
			item = statlist_pop(&oldPooler_list);
			pgOldSocket = container_of(item, PgOldSocket, head);
			err = use_pooler_socket(pgOldSocket->fd, pga_is_unix(&pgOldSocket->addr));
			if (!err) {
				return (void*)-1;
			}
			free(pgOldSocket);
		}
	} else { //normal start pgbouncer
		pooler_setup();
	}

	set_acceptSocketEB(pgThread);

	resume_pooler();

	setup_acceptThread_janitor(pgThread);

	while(cf_shutdown < 2) {
		err = event_base_loop(pgThread->eventBase, EVLOOP_ONCE);
		if (err < 0) {
			log_error("event base loop run error");
			return (void*)-1;
		}
		run_timerEvent(pgThread);
	}
	return (void*)0;
}

static void maintain_pooler(PgThread *pgThread)
{
	if (cf_pause_mode == P_SUSPEND && pooler_isActive()) {
		suspend_pooler();
	} else if (cf_pause_mode == P_NONE && !pooler_isActive()) {
		resume_pooler();
	} else {
		per_loop_pooler_maint();
	}
}

void add_acceptOldSocket(PgOldSocket* pgOldSocket)
{
	Assert(pgOldSocket != NULL);
	statlist_append(&oldPooler_list, &pgOldSocket->head);
}

void shutdown_acceptThread(void)
{
	shutdown_pgThread(acceptThread);
}

static void setup_acceptThread_janitor(PgThread *pgThread)
{
	/* launch maintenance */
	Assert(pgThread != NULL);
	pgbouncer_evtimer_set(pgThread->eventBase,
			&acceptThread_ev,
			do_acceptThread_maint, pgThread);

	add_safe_evtimer(pgThread, &acceptThread_ev,
			&acceptThread_period);
}

static void do_acceptThread_maint(int sock, short flags, void *arg)
{
	PgThread *pgThread = arg;
	maintain_pooler(pgThread);

	add_safe_evtimer(pgThread, &acceptThread_ev,
				&acceptThread_period);
}
