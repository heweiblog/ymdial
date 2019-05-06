#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "log.h"
#include "udp.h"
#include "work.h"
#include "icmp.h"


int new_udp_block_fd()
{
		int fd = socket(AF_INET, SOCK_DGRAM, 0);
		if(fd < 0)
		{
				return -1;
		}
		
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 10*1000;
		int rtn = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval));
		if(rtn < 0)
		{       
				close(fd);
				return -1;
		}

		timeout.tv_sec = 0;
		timeout.tv_usec= 80*1000;
		rtn = setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(struct timeval));
		if(rtn < 0)
		{       
				close(fd);
				return -1;
		}

		return fd;
}

void handle_udp_port_task(const char*ip,const int port,const char*policy,enum policy_type type)
{
		if(udp_queue.size() > 10000)
		{
				return;
		}

		ev_t * my_ev = (ev_t*)calloc(1,sizeof(ev_t));
		if(!my_ev)
		{
				LOG(WARNING)<<"my_ev calloc failed";
				exit_process();
		}

		my_ev->type = type;
		my_ev->port = port;
		strcpy(my_ev->ip,ip);
		strcpy(my_ev->policy,policy);
		
		pthread_mutex_lock(&udp_queue_lock);
		udp_queue.push(my_ev);
		pthread_mutex_unlock(&udp_queue_lock);
}


int new_raw_socket()
{
		int fd = socket(AF_INET, SOCK_RAW,IPPROTO_ICMP);
		if(fd < 0)
		{
				return -1;
		}

		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 10*1000;

		int rtn = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval));
		if(rtn < 0)
		{       
				close(fd);
				return -1;
		}

		timeout.tv_sec = 0;
		timeout.tv_usec = 80*1000;
		rtn = setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));
		if(rtn < 0)
		{   
				close(fd);
				return -1;
		} 
		
		return fd;
}


int do_udp_task(ev_t*ev)
{
		char answer[500] = {'\0'};
		char msg[8] = {'\0'};
		char remote_ip[32] = {'\0'};
		int anslen = 0,i = 0,res = 0,rtn = 0;
		socklen_t rlen = 0;

		if(ping_set.end() == ping_set.find(ev->ip))
		{
				handle_icmp_task(ev->ip);
				usleep(100*1000);
				if(ping_set.end() == ping_set.find(ev->ip))
				{
						LOG(WARNING)<<"the ip can not reach,ip="<<ev->ip;
						return -1;
				}
		}

		struct sockaddr_in servaddr;
		memset(&servaddr, 0, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons(ev->port);
		inet_pton(AF_INET,ev->ip,&servaddr.sin_addr.s_addr);

		int fd = new_udp_block_fd();
		int raw_fd = new_raw_socket();
		if(fd <= 0 || raw_fd <= 0) 
		{    
				LOG(ERROR)<<"create socket failed,ip="<<ev->ip;
				return -1;
		}
		
		for(i = 0 ; i < 3 ; i++)
		{       
				rtn = sendto(fd,msg,0,0,(struct sockaddr *)&servaddr,sizeof(struct sockaddr_in));
				if(rtn < 0)
				{       
						res = -1;
						break;
				}

				memset(answer,0,sizeof(answer));
				anslen = recvfrom(raw_fd,answer,sizeof(answer),0,NULL,NULL);

				if(anslen > 0 && !strcmp(ev->ip,inet_ntop(AF_INET,answer+12,remote_ip,32)) && (*(uint8_t*)(answer+20) == 3) && (*(uint8_t*)(answer+21) == 3))
				{
						res = -1;
						break;
				}
		}

		close(fd);
		close(raw_fd); 
		return res;
}


void* udp_dial_thread(void*arg)
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
				while(!udp_queue.empty())
				{
						pthread_mutex_lock(&udp_queue_lock);
						ev = udp_queue.front();
						udp_queue.pop();
						pthread_mutex_unlock(&udp_queue_lock);

						gettimeofday(&ev->t_start,NULL);
						rtn = do_udp_task(ev);
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


