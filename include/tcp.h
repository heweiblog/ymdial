#ifndef _UDP_H_
#define _UDP_H_

#include "common.h"
#include "epoll.h"

int new_unblock_tcp_socket();

int tcp_send_msg(ev_t*ev);

int tcp_recv_msg(ev_t*ev,char* recv_buf);

void handle_tcp_port_task(const char*ip,const int port,const char* policy,enum policy_type type);

#endif
