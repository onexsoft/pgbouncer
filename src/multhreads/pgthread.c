/*
 * pgthread.c
 *
 *  Created on: 20150808
 *      Author: huih
 */

#include "bouncer.h"

static int get_threadIndex(void)
{
	static int currentThreadIndex = 0;
	return currentThreadIndex ++;
}

PgThread* new_pgThread(const char* threadName)
{
	PgThread *pgThread = NULL;
	int err = -1;

	Assert(threadName != NULL);
	//init
	pgThread = (PgThread*)malloc(sizeof(PgThread));
	if (pgThread == NULL)
	{
		log_error("malloc pgThread error\n");
		return pgThread;
	}

	{
		pgThread->threadIndex = get_threadIndex();
		pgThread->tid = 0;
		pgThread->name = threadName;

		pgThread->current_timer_backup_index = 0;

		pgThread->eventBase = event_base_new();
		if (pgThread->eventBase == NULL)
		{
			log_error("event_base_new error, current_thread_index: %d\n", pgThread->threadIndex);
			return NULL;
		}

		err = pthread_mutex_init(&pgThread->threadMutex, NULL);
		if (err < 0)
		{
			log_error("pthread_mutex_init err, errno: %d, errstr: %s\n", errno, strerror(errno));
			return NULL;
		}

		err = pthread_cond_init(&pgThread->threadCond, NULL);
		if (err < 0)
		{
			log_error("pthread_cond_init err, errno: %d, errstr: %s\n", errno, strerror(errno));
			return NULL;
		}
	}
	return pgThread;
}

void destroy_pgThread(PgThread* pgThread)
{
	if (pgThread->eventBase != NULL) {
		event_base_free(pgThread->eventBase);
	}

	pthread_mutex_destroy(&pgThread->threadMutex);
	pthread_cond_destroy(&pgThread->threadCond);

	if (pgThread != NULL) {
		free(pgThread);
		pgThread = NULL;
	}
}

void run_timerEvent(PgThread* pgThread)
{
	struct timer_slot *ts;
	Assert(pgMulThread != NULL);
	while (pgThread->current_timer_backup_index > 0) {
		ts = &pgThread->timer_backup_list[pgThread->current_timer_backup_index - 1];
		if (evtimer_add(ts->ev, &ts->tv) < 0)
			break;
		pgThread->current_timer_backup_index--;
	}
}

void add_safe_evtimer(PgThread* pgThread, struct event *ev, struct timeval *tv)
{
	int res;
	struct timer_slot *ts;

	Assert(pgMulThread != NULL);
	res = evtimer_add(ev, tv);
	if (res >= 0)
		return;

	if (pgThread->current_timer_backup_index >= MAX_TIMER_BACKUP_SLOT)
		fatal_perror("TIMER_BACKUP_SLOTS full");

	ts = &pgThread->timer_backup_list[pgThread->current_timer_backup_index++];
	ts->ev = ev;
	ts->tv = *tv;
}

void shutdown_pgThread(PgThread * pgThread)
{
	event_base_loopbreak(pgThread->eventBase);
	pthread_mutex_lock(&pgThread->threadMutex);
	pthread_cond_signal(&pgThread->threadCond);
	pthread_mutex_unlock(&pgThread->threadMutex);
}
