/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 * 
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
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

void janitor_setup(void);
void config_postprocess(void);
void resume_all(void);
void per_loop_maint(void);
bool suspend_socket(PgSocket *sk, bool force)  _MUSTCHECK;
void kill_pool(PgPool *pool);
void launch_recheck(PgPool *pool);
void close_server_list(struct StatList *sk_list, const char *reason);
void close_client_list(struct StatList *sk_list, const char *reason);
void close_reqtimeout_client_list(struct StatList *sk_list, const char *reason);
void close_conntimeout_client_list(struct StatList *sk_list, const char *reason);
int suspend_socket_list(struct StatList *list, bool force_suspend);
void pool_server_maint(PgPool *pool);
void check_pool_size(PgPool *pool);
void handing_pool_waitTestServer(PgPool *pool);

//add by huih@20150827
void resume_socket_list(struct StatList *list);

