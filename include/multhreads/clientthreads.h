/*
 * multhreads.h
 *
 *  Created on: 2015723
 *      Author: April
 */

#ifndef INCLUDE_MULTHREADS_CLIENTTHREADS_H_
#define INCLUDE_MULTHREADS_CLIENTTHREADS_H_
#include <usual/pthread.h>
#include <usual/statlist.h>
#include "multhreads/pgthread.h"

extern struct StatList clientThread_list;//add by huih@20150723
extern struct StatList cancel_client_list;//add by huih@20150803
extern struct StatList oldClientSocket_list;//add by huih@20150826
extern pthread_mutex_t cancel_client_mutex;


/**
 * new many base_event to handle read and write data
 * add by huih@20150723
 * **/
typedef struct PgCLThread {
	struct List head;
	PgThread *thread;
	int thread_num;  //the number of threads
	int current_thread_index; //current thread index
	struct StatList connectList;
	struct StatList loginList;
	struct StatList waitingList;
	struct StatList activeList;
	struct StatList justfreeList;
	struct StatList disConnectList;/*need to run disconnect operation*/
	struct StatList serverList; /*apply for server for client thread*/
	struct StatList oldActiveList;

	struct event timer_evt; //timering event.
	struct event monitor_evt;

}PgCLThread;

//init mul threads
int init_clientThread(void);

//destory multhread
void destroy_clientThread(void);

//handle client request
int handle_client_use_clientThread(int fd, bool is_unix);

PgCLThread* malloc_PGCLThread(PgThread* pgThread);

//add by huih@20150826
void add_clientOldSocket(PgOldSocket* pgOldSocket);

void shutdown_clientThread(void);
#endif /* INCLUDE_MULTHREADS_CLIENTTHREADS_H_ */
