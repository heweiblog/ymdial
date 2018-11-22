#include <arpa/inet.h>
#include "log.h"
#include "tcp.h"
#include "server.h"
#include "work.h"
#include "mysql.h"
#include "ftp.h"

#define FTP_PORT 21
#define TFP_USER "anonymous"
#define TFP_PASS "anonymous"

int get_db_param_from_url(const char *ip,const char *url,char *host,int *port,char *db_name,char *usr,char *pwd)
{
		char *pstart = NULL;
		char *phost = host;
		char pport[10] = {0};
		int i = 0;

		if(NULL == url) {
				return -1;
		}

		pstart = (char*)strstr(url,"mysql://");
		if(NULL == pstart) {
				return -1;	
		}else {
				pstart += strlen("mysql://");

		}

		//提取host
		while(*pstart != '\0') {
				if(':' == *pstart || '/' == *pstart) {
						break;
				}else {
						*host++ = *pstart++;
				}
		}
		if(*pstart == '\0') {
				return -1;	
		}

		if(!strcmp("$domain",phost))
				strcpy(phost,ip);

		if(':' == *pstart) {
				pstart++;
				//提取port
				while(*pstart != '\0') {
						if('/' == *pstart)
								break;
						else
								pport[i++] = *pstart++;
				}	
				if(*pstart == '\0') {
						return -1;	
				}

				*port = atoi(pport);
		}else {
				*port = 3306;//mysql
		}

		pstart++;
		//提取db name
		while(*pstart != '\0') {
				if('?' == *pstart) {
						break;
				}else {
						*db_name++ = *pstart++;
				}
		}
		if(*pstart == '\0') {
				return -1;	
		}

		pstart++;
		//提取user
		pstart = strstr(pstart,"user=");
		if(NULL == pstart) {
				return -1;
		} else {
				pstart += strlen("user=");

				while(*pstart != '\0') {
						if('&' == *pstart) {
								break;
						}else {
								*usr++ = *pstart++;
						}
				}	
				if(*pstart == '\0') {
						return -1;	
				}
		}

		pstart++;
		//提取pwd
		pstart = strstr(pstart,"password=");
		if(NULL == pstart) {
				return -1;
		} else {
				pstart += strlen("password=");

				while(*pstart != '\0') {
						if('&' == *pstart) {
								break;
						}else {
								*pwd++ = *pstart++;
						}
				}		
				if(*pstart == '\0') {
						return -1;	
				}
		}

		return 0;
}


void handle_mysql_task(const char* ip,const char* policy,enum policy_type type)
{
		int fd = new_unblock_tcp_socket();
		if(fd < 0)
		{
				LOG(ERROR)<<"create unblock tcp fd failed,ip="<<ip;
				return;
		}
	
		ev_t * my_ev = (ev_t*)calloc(1,sizeof(ev_t));
		if(!my_ev)
		{
				LOG(WARNING)<<"my_ev calloc failed";
				exit_process();
		}

		my_ev->fd = fd;
		my_ev->type = type;
		strcpy(my_ev->ip,ip);
		strcpy(my_ev->policy,policy);

		login_t* sql = (login_t*)calloc(1,sizeof(login_t));
		if(!sql)
		{
				LOG(WARNING)<<"my_ev calloc failed";
				exit_process();
		}
		
		char host[32] = {'\0'};
		int rtn = get_db_param_from_url(ip,policy_map[policy].option.destUrl.c_str(),host,&sql->port,sql->db,sql->user,sql->pwd);
		if(rtn < 0)
		{
				update_dial_result(my_ev,false);
				LOG(WARNING)<<"get_db_param_from_url faild ip="<<ip;
				free(sql);
				free(my_ev);
				return;
		}
		strcpy(sql->method,policy_map[policy].option.testMethod.c_str());

		my_ev->sql =sql;

		if(tcp_epoll_add(fd,my_ev) < 0)
		{
				LOG(ERROR)<<"add tcp ev fd failed,ip="<<my_ev->ip;
				tcp_ev_del(my_ev);
				return;
		}

		struct sockaddr_in dest;
		dest.sin_family = AF_INET;
		dest.sin_port = htons(sql->port);
		inet_pton(AF_INET,ip,&dest.sin_addr);

		connect(fd,(struct sockaddr*)&dest,sizeof(sockaddr_in));
		
}

int result_mysql_query(MYSQL *conn,char *cmd)
{
		MYSQL_RES *result = NULL;

		if(0 != mysql_real_query(conn,cmd,strlen(cmd))) 
		{
				return -1;
		}

		result = mysql_store_result(conn); 
		int num_rows = mysql_num_rows(result);
		mysql_free_result(result);

		if(num_rows <= 0)
		{
				return -1;
		}		
		return 0;
}

int do_mysql_task(ev_t* ev)
{
		MYSQL* conn = mysql_init(NULL);
		if(NULL == conn) 
		{
				LOG(ERROR)<<"mysql init failed,ip="<<ev->ip;
				return -1;
		}
		if(NULL == mysql_real_connect(conn,ev->ip,ev->sql->user,ev->sql->pwd,ev->sql->db,ev->sql->port,NULL,0)) 
		{
				LOG(ERROR)<<"mysql open failed,ip="<<ev->ip;
				return -1;
		}

		int rtn = result_mysql_query(conn,ev->sql->method);
		mysql_close(conn);

		return rtn;
}

void handle_ftp_task(const char*ip,const int port,const char*policy,enum policy_type type)
{
		int fd = new_unblock_tcp_socket();
		if(fd < 0)
		{
				LOG(ERROR)<<"create unblock tcp fd failed,ip="<<ip;
				return;
		}
	
		ev_t * my_ev = (ev_t*)calloc(1,sizeof(ev_t));
		if(!my_ev)
		{
				LOG(WARNING)<<"my_ev calloc failed";
				exit_process();
		}

		my_ev->fd = fd;
		my_ev->type = type;
		strcpy(my_ev->ip,ip);
		strcpy(my_ev->policy,policy);

		login_t* sql = (login_t*)calloc(1,sizeof(login_t));
		if(!sql)
		{
				LOG(WARNING)<<"my_ev calloc failed";
				exit_process();
		}
	
		sql->port = port;	
		strcpy(sql->user,policy_map[policy].option.destUrl.c_str());
		strcpy(sql->pwd,policy_map[policy].option.testMethod.c_str());

		my_ev->sql =sql;

		if(tcp_epoll_add(fd,my_ev) < 0)
		{
				LOG(ERROR)<<"add tcp ev fd failed,ip="<<my_ev->ip;
				tcp_ev_del(my_ev);
				return;
		}

		struct sockaddr_in dest;
		dest.sin_family = AF_INET;
		dest.sin_port = htons(sql->port);
		inet_pton(AF_INET,ip,&dest.sin_addr);

		connect(fd,(struct sockaddr*)&dest,sizeof(sockaddr_in));
}


int do_ftp_task(ev_t* ev)
{
		int rtn = login_ftp(ev->ip,ev->sql->user,ev->sql->pwd);
		
		if(rtn == 1)
		{
				//LOG(INGO)<<"ftp"<<"ip="<ev->ip
				return 0;
		}
		return -1;
}

void* mysql_dial_thread(void*arg)
{
		int rtn = 0;
		ev_t * ev = NULL;

		while(true)
		{
				if(!dial_status || !register_status)
				{
						sleep(1);
						continue;
				}
				while(!common_queue.empty())
				{
						pthread_mutex_lock(&common_queue_lock);
						ev = common_queue.front();
						common_queue.pop();
						pthread_mutex_unlock(&common_queue_lock);

						gettimeofday(&ev->t_start,NULL);
						if(ev->type == DIAL_DATABASE)
						{
								rtn = do_mysql_task(ev);
						}
						else if(ev->type == DIAL_FTP)
						{
								rtn = do_ftp_task(ev);
						}

						if(!rtn)
						{
								update_dial_result(ev,true);
						}
						else
						{
								update_dial_result(ev,false);
						}
						free(ev->sql);
						free(ev);
				}
				sleep(1);
		}
}











