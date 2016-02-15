/*
 * pgthread.h
 *
 *  Created on: 20150808
 *      Author: huih
 */

#ifndef INCLUDE_MULTHREADS_PGTHREAD_H_
#define INCLUDE_MULTHREADS_PGTHREAD_H_

typedef struct timer_slot {
	struct event *ev;
	struct timeval tv;
}TimerSlot;

typedef struct PgThread {
	pthread_t tid;//thread id
	const char* name; //thread name
	int threadIndex; //record sum thread

	struct event_base *eventBase;//current thread use event base.

	pthread_mutex_t threadMutex;
	pthread_cond_t threadCond;

	//define timing event
#define MAX_TIMER_BACKUP_SLOT 10
	TimerSlot timer_backup_list[MAX_TIMER_BACKUP_SLOT];
	int current_timer_backup_index;
}PgThread;

PgThread* new_pgThread(const char* threadName);

void destroy_pgThread(PgThread* );

void run_timerEvent(PgThread* );

void add_safe_evtimer(PgThread* pgThread, struct event *ev, struct timeval *tv);

void shutdown_pgThread(PgThread *);

#endif /* INCLUDE_MULTHREADS_PGTHREAD_H_ */
