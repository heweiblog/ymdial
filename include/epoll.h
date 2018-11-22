#ifndef _EPOLL_H_
#define _EPOLL_H_

#include <sys/epoll.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "common.h"
#include "mysql.h"

#define EPOLL_SIZE 65535
#define EVENT_SIZE 2000


typedef struct common_event
{
		enum policy_type type;
		char ip[32];
		char policy[32];
		char send_buf[4096];
		int send_len;
		int fd;
		int flag;
		int port;
		struct timeval t_start;
		SSL_CTX * ctx;
		SSL * ssl;
		login_t* sql;

}ev_t;

int init_epoll();

void init_ssl();

int udp_epoll_add(int fd,ev_t*ev);

int tcp_epoll_add(int fd,ev_t*ev);
void tcp_ev_del(ev_t*ev);

int https_epoll_add(int fd,ev_t*ev);
void https_ev_del(ev_t*ev);

void update_dial_result(ev_t* ev,bool result);

void *common_epoll_thread(void* arg);
void *https_epoll_thread(void* arg);


#endif
