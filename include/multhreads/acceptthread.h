/*
 * acceptthread.h
 *
 *  Created on: 20150808
 *      Author: hui
 */

#ifndef INCLUDE_MULTHREADS_ACCEPTTHREAD_H_
#define INCLUDE_MULTHREADS_ACCEPTTHREAD_H_

extern struct StatList oldPooler_list;

//init accept thread
int init_acceptThread(void);

//destroy accept thread.
void destory_acceptThread(void);

//add by huih@20150826
void add_acceptOldSocket(PgOldSocket *pgOldSocket);

//shut down accept thread,add by huih@20150827
void shutdown_acceptThread(void);
#endif /* INCLUDE_MULTHREADS_ACCEPTTHREAD_H_ */
