#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "log.h"
#include "dial_server.h"
#include "server.h"
#include "work.h"
#include "conf.h"
#include "http.h"

int g_dns_fd = 0;
int g_dnsv6_fd = 0;

int new_tcp_block_fd(bool is_ipv6)
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
		timeout.tv_usec= 100*1000;
		rtn = setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(struct timeval));
		if(rtn < 0)
		{       
				close(fd);
				return -1;
		}
		
		return fd;
}

int handle_http_server_dial(const char* ip)
{
		int rtn = 0;
		bool is_ipv6 = false;
		if(strstr(ip,"::"))
		{
				is_ipv6 = true;
		}
		int fd = new_tcp_block_fd(is_ipv6);
		if(fd <= 0)
		{
				LOG(ERROR)<<"create tcp block fd failed";
				return -1;
		}

		char send_buf[512] = {'\0'};
		sprintf(send_buf,http_get,"/",ip);

		if(is_ipv6)
		{
				struct sockaddr_in6 dest;
				dest.sin6_family = AF_INET6;
				dest.sin6_port = htons(HTTP_PORT);
				inet_pton(AF_INET6,ip,&dest.sin6_addr);

				rtn = connect(fd,(struct sockaddr*)&dest,sizeof(sockaddr_in6));
		}
		else
		{
				struct sockaddr_in dest;
				dest.sin_family = AF_INET;
				dest.sin_port = htons(HTTP_PORT);
				inet_pton(AF_INET,ip,&dest.sin_addr);

				rtn = connect(fd,(struct sockaddr*)&dest,sizeof(sockaddr_in));
		}
		if(rtn < 0)
		{
				close(fd);
				return -1;
		}
		
		int size = send(fd,send_buf,strlen(send_buf),0);
		if(size < 0)
		{
				close(fd);
				return -1;
		}

		char recv_buf[512] = {'\0'};
		struct timeval t_start;
		struct timeval t_end;

		gettimeofday(&t_start,NULL);

		size = recv(fd,recv_buf,512,0);
		if(size < 0)
		{
				close(fd);
				return -1;
		}

		gettimeofday(&t_end,NULL);

		close(fd);
		return ((t_end.tv_sec * 1000*1000 + t_end.tv_usec) - (t_start.tv_sec * 1000*1000 + t_start.tv_usec));
}

int create_udp_fd(bool is_ipv6)
{       
		int rtn = 0,fd = 0;
		struct timeval timeout;
		
		if(is_ipv6)
		{
				fd = socket(AF_INET6,SOCK_DGRAM,0);
		}
		else
		{
				fd = socket(AF_INET,SOCK_DGRAM,0);
		}
		if(fd <= 0)
		{       
				return -1;
		}

		timeout.tv_sec = 0;
		timeout.tv_usec = 100*1000;
		rtn = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval));
		if(rtn < 0)
		{       
				close(fd);
				return -1;
		}

		timeout.tv_sec = 0;
		timeout.tv_usec=(cfg.timeout + 1)*1000;
		rtn = setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(struct timeval));
		if(rtn < 0)
		{       
				close(fd);
				return -1;
		}

		return fd;
}


int request_dns_server(const char*srv_addr)
{
		struct timeval t_start,t_end;
		u_char msg[NS_PACKETSZ] = {'\0'};
		u_char answer[NS_PACKETSZ] = {'\0'};
		int msglen = res_mkquery(QUERY,cfg.dname,ns_c_in,ns_t_a,NULL,0,NULL,msg,NS_PACKETSZ);

		if(strstr(srv_addr,"::"))
		{
				struct sockaddr_in6 addr;
				addr.sin6_family = AF_INET6;
				addr.sin6_port = htons(NS_DEFAULTPORT);
				inet_pton(AF_INET6,srv_addr,&addr.sin6_addr);
				
				int rtn = sendto(g_dnsv6_fd,msg,msglen,0,(const struct sockaddr *)&addr,sizeof(addr));
				if(rtn < 0)
				{   
						LOG(ERROR)<<"send dns msg failed dns_srv="<<srv_addr;
						return cfg.timeout;
				}   

				gettimeofday(&t_start,NULL);
				recvfrom(g_dnsv6_fd,answer,NS_PACKETSZ,0,NULL,NULL);
		}
		else
		{
				struct sockaddr_in addr;
				addr.sin_family = AF_INET;
				addr.sin_port = htons(NS_DEFAULTPORT);
				inet_pton(AF_INET,srv_addr, &addr.sin_addr.s_addr);

				int rtn = sendto(g_dns_fd,msg,msglen,0,(const struct sockaddr *)&addr,sizeof(addr));
				if(rtn < 0)
				{   
						LOG(ERROR)<<"send dns msg failed dns_srv="<<srv_addr;
						return cfg.timeout;
				}   

				gettimeofday(&t_start,NULL);
				recvfrom(g_dns_fd,answer,NS_PACKETSZ,0,NULL,NULL);
		}
		
		gettimeofday(&t_end,NULL);
		return ((t_end.tv_sec * 1000*1000 + t_end.tv_usec) - (t_start.tv_sec * 1000*1000 + t_start.tv_usec));

}

int handle_dns_dial(const char* srv_addr)
{
		int i = 0,rtn = 0,delay = 0;
		int success = 0;
		int timeout = 0;
		int health_value = 0;

		for(i = 0 ; i < cfg.count ; i++)
		{
				rtn = request_dns_server(srv_addr);
				if(rtn < cfg.timeout*1000) 
				{
						success++;
						timeout += rtn;
				}
		}

		if(success > 0)
		{
				delay = timeout/success;
				health_value = (timeout/1000/success*cfg.delay_weight) + (cfg.count - success)*cfg.lost_weight;
				if(health_value < cfg.health) 
				{
						return delay;
				}
		}

		return -1;
}

void *server_dial_thread(void*arg)
{
		server_results.clear();
		int i = 0,rtn = 0;
		time_t t_start = time(NULL);
		time_t t_now = 0;
		map<string,server_node_t>::iterator iter;
		vector<string>::iterator policy_iter;

		g_dns_fd = create_udp_fd(false);
		if(g_dns_fd <= 0)
		{
				LOG(WARNING)<<"create g_dns_fd failed";
				exit_process();
		}
		g_dnsv6_fd = create_udp_fd(true);
		if(g_dnsv6_fd <= 0)
		{
				LOG(WARNING)<<"create g_dnsv6_fd failed";
				exit_process();
		}

		LOG(INFO)<<"udp_dns_fd="<<g_dns_fd<<",udp_dnsv6_fd="<<g_dnsv6_fd;

		DialServerResult server_result;

		while(true)
		{
				if(!dial_status || !register_status)
				{
						sleep(1);
						continue;
				}

				t_now = time(NULL);

				pthread_rwlock_rdlock(&server_map_lock);

				for(iter = server_map.begin() ; iter != server_map.end() ; iter++)
				{
						if(DialServerType::XPROXY == iter->second.srv_type || DialServerType::XFORWARD == iter->second.srv_type)
						{
								if(0 == ((t_now - t_start) % cfg.interval))
								{
										server_result.typ = iter->second.srv_type;
										server_result.status.rid = iter->first;
										server_result.status.ip = iter->second.ip;

										rtn = handle_dns_dial(iter->second.ip.addr.c_str());
										if(rtn > 0)
										{
												server_result.status.status = DialStatus::OK;
												server_result.status.delay = rtn;
										}
										else
										{
												server_result.status.status = DialStatus::FAIL;
												server_result.status.delay = 0;
										}

										server_results.push_back(server_result);
										LOG(INFO)<<"dns server dial result:server_id="<<server_result.status.rid<<",ip="<<server_result.status.ip.addr<<",status="<<server_result.status.status;
								}	
						}
						else if(DialServerType::REDIRECT == iter->second.srv_type)
						{
								if(0 == ((t_now - t_start) % cfg.interval))
								{
										server_result.typ = iter->second.srv_type;
										server_result.status.rid = iter->first;
										server_result.status.ip = iter->second.ip;

										rtn = handle_http_server_dial(iter->second.ip.addr.c_str());
										if(rtn > 0)
										{
												server_result.status.status = DialStatus::OK;
												server_result.status.delay = rtn;
										}
										else
										{
												server_result.status.status = DialStatus::FAIL;
												server_result.status.delay = 0;
										}

										server_results.push_back(server_result);
										LOG(INFO)<<"redirect dial result:server_id="<<server_result.status.rid<<",ip="<<server_result.status.ip.addr<<",status="<<server_result.status.status;
								}
						}
				}

				pthread_rwlock_unlock(&server_map_lock);

				if(server_results.size() > 2000 || ((0 == ((t_now-t_start) % 5)) && (server_results.size() > 0)))
				{
						update_dial_status(SERVER);
						server_results.clear();
				}

				sleep(1);
		}
}

