#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "common.h"
#include "log.h"
#include "tcp.h"
#include "epoll.h"
#include "smtp.h"

int new_unblock_tcp_socket(bool is_ipv6)
{
		int fd = 0;

		if(is_ipv6)
		{
				fd = socket(AF_INET6, SOCK_STREAM, 0);
		}
		else
		{
				fd = socket(AF_INET, SOCK_STREAM, 0);
		}
		if(fd <= 0)
		{
				return -1;
		}

		if(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0)
		{
				close(fd);
				return -1;
		}

		int n = 1;
		if(0 != setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&n, sizeof(int)))
		{
				close(fd);
				return -1;
		}

		return fd;
}

int tcp_send_msg(ev_t*ev)
{
		int size = 0;

		while((size = send(ev->fd,ev->send_buf,ev->send_len,0)) < 0)
		{
				if(errno == EINTR || errno == EAGAIN)
				{
						continue;
				}
				LOG(ERROR)<<"tcp send msg failed,ip="<<ev->ip<<",errno="<<errno;
				return -1;
		}
		if(size == ev->send_len)
		{
				return 0;
		}		
		LOG(WARNING)<<"tcp send msg failed,ip="<<ev->ip;
		return -1;
}

int tcp_recv_msg(ev_t*ev,char*recv_buf)
{
		int rtn = 0,size = 0;

		do
		{
				rtn = recv(ev->fd,recv_buf+size,1024,0);
				if(rtn < 0)
				{
						if((errno == EINTR || errno == EAGAIN))
						{
								continue;
						}
						LOG(ERROR)<<"tcp recv msg failed,ip="<<ev->ip<<",errno="<<errno;
						return -1;
				}
				size += rtn;
		}
		while(rtn > 0 && size < 1024*1023);

		return size;
}
		

void connect_server(bool is_ipv6,const char*ip,const int port,int fd)
{
		if(is_ipv6)
		{
				struct sockaddr_in6 dest;
				dest.sin6_family = AF_INET6;
				dest.sin6_port = htons(port);
				inet_pton(AF_INET6,ip,&dest.sin6_addr);

				connect(fd,(struct sockaddr*)&dest,sizeof(sockaddr_in6));
		}
		else
		{
				struct sockaddr_in dest;
				dest.sin_family = AF_INET;
				dest.sin_port = htons(port);
				inet_pton(AF_INET,ip,&dest.sin_addr);

				connect(fd,(struct sockaddr*)&dest,sizeof(sockaddr_in));
		}
}


void handle_tcp_port_task(const char*ip,const int port,const char*policy,enum policy_type type)
{
		bool is_ipv6 = false;
		if(strstr(ip,"::"))
		{
				is_ipv6 = true;
		}
		int fd = new_unblock_tcp_socket(is_ipv6);
		if(fd < 0)
		{
				LOG(WARNING)<<"create unblock tcp fd failed,ip="<<ip;
				exit_process();
		}
	
		ev_t * my_ev = (ev_t*)calloc(1,sizeof(ev_t));
		if(!my_ev)
		{
				LOG(WARNING)<<"calloc failed,ip="<<ip;
				exit_process();
		}

		my_ev->fd = fd;
		my_ev->type = type;
		strcpy(my_ev->ip,ip);
		strcpy(my_ev->policy,policy);
		if(type == DIAL_SMTP)
		{
				strcpy(my_ev->send_buf,SMTP_MSG);
				my_ev->send_len = strlen(my_ev->send_buf);
		}

		gettimeofday(&my_ev->t_start,NULL);
		
		if(tcp_epoll_add(fd,my_ev) < 0)
		{
				LOG(WARNING)<<"add tcp ev fd failed,ip="<<my_ev->ip;
				tcp_ev_del(my_ev);
				return;
		}

		connect_server(is_ipv6,ip,port,fd);
}


