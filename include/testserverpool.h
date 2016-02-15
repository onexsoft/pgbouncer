/*
 * testserverpool.h
 *
 *  Created on: 201589
 *      Author: hui
 */

#ifndef INCLUDE_TESTSERVERPOOL_H_
#define INCLUDE_TESTSERVERPOOL_H_

#ifdef TEST_APP_PERF
#include <gperftools/profiler.h>
#endif

#ifdef TEST_APP_PERF
#define START_TEST_APP_PERF ProfilerStart("pgbouncer.prof");
#else
#define START_TEST_APP_PERF
#endif

#ifdef TEST_APP_PERF
#define END_TEST_APP_PERF ProfilerStop();
#else
#define END_TEST_APP_PERF ;
#endif

void serverPool_monitor(PgThread* pgThread);
void serverPool_print(void);
void serverPool_new_pool(void);

void print_event_log(int severity, const char *msg);
void clientThread_monitor(PgCLThread* pgCLThread);


#endif /* INCLUDE_TESTSERVERPOOL_H_ */
