#ifndef _MYSQL_H_
#define _MYSQL_H_

#include <mysql/mysql.h>
#include "common.h"

typedef struct login_node
{
		char db[128];
		char method[128];
		char user[32];
		char pwd[32];
		int port;

}login_t;

void handle_db_task(const char* ip,const char* policy,enum policy_type type);
void handle_ftp_task(const char*ip,const int port,const char*policy,enum policy_type type);
void* mysql_dial_thread(void*arg);

#endif
