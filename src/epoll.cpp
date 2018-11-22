#include <pthread.h>
#include "log.h"
#include "server.h"
#include "epoll.h"
#include "work.h"
#include "tcp.h"
#include "http.h"
#include "mysql.h"

int g_epoll_common_fd = 0;
int g_epoll_https_fd = 0;


void init_ssl()
{
		SSL_load_error_strings();
		SSL_library_init();

		ERR_load_BIO_strings();
		OpenSSL_add_all_algorithms();
}

int init_epoll()
{
		if((g_epoll_common_fd = epoll_create(EPOLL_SIZE)) < 0)
		{
				return -1;
		}		

		if((g_epoll_https_fd = epoll_create(EPOLL_SIZE)) < 0)
		{
				return -1;
		}		
		LOG(INFO)<<"create epoll fd success,g_epoll_common_fd="<<g_epoll_common_fd<<",g_epoll_https_fd="<<g_epoll_https_fd;
		return 0;
}

int udp_epoll_add(int fd,ev_t* my_ev)
{
		struct epoll_event ev;
		ev.events = EPOLLIN;
		ev.data.ptr = my_ev;

		if(epoll_ctl(g_epoll_common_fd,EPOLL_CTL_ADD,fd,&ev) < 0)
		{
				return -1;
		}
		return 0;
}

int tcp_epoll_add(int fd,ev_t* my_ev)
{
		struct epoll_event ev;
		ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
		ev.data.ptr = my_ev;

		if(epoll_ctl(g_epoll_common_fd,EPOLL_CTL_ADD,fd,&ev) < 0)
		{
				return -1;
		}
		return 0;
}

void tcp_ev_del(ev_t*ev)
{
		if(epoll_ctl(g_epoll_common_fd,EPOLL_CTL_DEL,ev->fd,NULL) < 0)
		{
				LOG(ERROR)<<"del tcp epoll fd failed,ip="<<ev->ip;
		}
		close(ev->fd);
		free(ev);
}

int https_epoll_add(int fd,ev_t* my_ev)
{
		struct epoll_event ev;
		ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
		ev.data.ptr = my_ev;

		if(epoll_ctl(g_epoll_https_fd,EPOLL_CTL_ADD,fd,&ev) < 0)
		{
				return -1;
		}
		return 0;
}

void https_ev_del(ev_t*ev)
{
		if(epoll_ctl(g_epoll_https_fd,EPOLL_CTL_DEL,ev->fd,NULL) < 0)
		{
				LOG(ERROR)<<"del https epoll fd failed,ip="<<ev->ip;
		}
		if(ev->ssl)
		{
				SSL_shutdown(ev->ssl);
				SSL_free(ev->ssl);
		}
		if(ev->ctx)
		{
				SSL_CTX_free(ev->ctx);
		}
		close(ev->fd);
		free(ev);
}

void update_dial_result(ev_t* ev,bool result)
{
		vector<ip_policy_result_t>::iterator result_iter;
		string policy(ev->policy);
		struct timeval t_end;
		gettimeofday(&t_end,NULL);

		pthread_mutex_lock(&ip_map[ev->ip].mutex);

		for(result_iter = ip_map[ev->ip].ip_policy_result.begin() ; result_iter != ip_map[ev->ip].ip_policy_result.end() ; result_iter++)
		{
				if(policy == result_iter->policyname)
				{
						result_iter->dial_flag = true;
						if(result)
						{
								result_iter->status = DialStatus::OK;
								result_iter->delay = SUB_TIME(t_end,ev->t_start);
						}
						else
						{
								result_iter->status = DialStatus::FAIL;
								result_iter->delay = 0;
						}
						break;
				}
		}

		pthread_mutex_unlock(&ip_map[ev->ip].mutex);
}

int do_send(ev_t*ev)
{
		switch(ev->type)
		{
				case DIAL_TCPPORT:
				{
						update_dial_result(ev,true);
						tcp_ev_del(ev);
						return 0;
				}
				case DIAL_DATABASE:
				case DIAL_FTP:
				{
						if(epoll_ctl(g_epoll_common_fd,EPOLL_CTL_DEL,ev->fd,NULL) < 0)
						{
								LOG(ERROR)<<"del tcp epoll fd failed,ip="<<ev->ip;
						}
						close(ev->fd);
						pthread_mutex_lock(&common_queue_lock);
						common_queue.push(ev);
						pthread_mutex_unlock(&common_queue_lock);
						return 0;
				}
				case DIAL_HTTPGET:
				case DIAL_EXTHTTPGET:
				case DIAL_EXTHTTPPOST:
				case DIAL_HTTPCOMMON:
				case DIAL_EXTTCPPORT:
				case DIAL_SMTP:
				{
						return tcp_send_msg(ev);
				}
		}
}


int recv_msg_check_result(ev_t*ev)
{
		char* recv_buf = (char*)calloc(1,1024*1024);
		int size = tcp_recv_msg(ev,recv_buf);
		if(size > 0)
		{
				int len = policy_map[ev->policy].option.expectMatch.size();
				if(len > 0)
				{
						if(!strstr(recv_buf,policy_map[ev->policy].option.expectMatch.c_str()))
						{
								free(recv_buf);
								return -1;
						}
				}
				int code_num = policy_map[ev->policy].option.expectCode.size();
				if(code_num > 0)
				{
						int i = 0;
						int status_code = atoi(recv_buf+9);
						for(i = 0 ; i < code_num ; i++)
						{
								if(status_code == policy_map[ev->policy].option.expectCode[i])
								{
										break;
								}
						}
						if(i == code_num)
						{
								free(recv_buf);
								return -1;
						}
				}
				free(recv_buf);
				return 0;
		}
		free(recv_buf);
		return -1;
}

int do_recv(ev_t*ev)
{
		int rtn = -1;

		switch(ev->type)
		{
				case DIAL_HTTPGET:
				{
						char* recv_buf = (char*)calloc(1,1024*1024);
						int size = tcp_recv_msg(ev,recv_buf);
						if(size > 0)
						{
								rtn = 0;
						}
						free(recv_buf);
						break;
				}
				case DIAL_EXTHTTPGET:
				case DIAL_EXTHTTPPOST:
				case DIAL_HTTPCOMMON:
				case DIAL_EXTTCPPORT:
				{
						rtn = recv_msg_check_result(ev);			
						break;
				}
				case DIAL_SMTP:
				{
						char* recv_buf = (char*)calloc(1,1024*1024);
						int size = tcp_recv_msg(ev,recv_buf);
						if(size > 0)
						{
								if(strstr(recv_buf,"220") || strstr(recv_buf,"250"))
								{
										free(recv_buf);
										return 0;
								}
						}
						free(recv_buf);
						return -1;
				}
		}

		return rtn; 
}

void *common_epoll_thread(void* arg)
{
		struct epoll_event events[EVENT_SIZE];
		int fds = 0, i = 0,rtn = 0;

		while(true)
		{
				fds = epoll_wait(g_epoll_common_fd,events,EVENT_SIZE,-1);

				if(fds == -1 && errno == EINTR)
				{
						continue;
				}
				for(i = 0 ; i < fds ; i++)
				{
						ev_t* ev = (ev_t*)events[i].data.ptr;
						
						if(events[i].events & EPOLLERR)
						{
								update_dial_result(ev,false);
								tcp_ev_del(ev);
						}
						else if(events[i].events == EPOLLOUT)
						{
								rtn = do_send(ev);
								if(rtn < 0)
								{
										update_dial_result(ev,false);
										tcp_ev_del(ev);
								}
						}
						else if(events[i].events == (EPOLLOUT | EPOLLIN))
						{
								rtn = do_recv(ev);
								if(!rtn)
								{
										update_dial_result(ev,true);
								}
								else
								{
										update_dial_result(ev,false);
								}
								tcp_ev_del(ev);
						}
				}
		}
}

int ssl_connect_write(ev_t*ev)
{
		int rtn = 0;
		int ssl_conn_ret = SSL_connect(ev->ssl);
		if (1 == ssl_conn_ret) 
		{
				while((rtn = SSL_write(ev->ssl,ev->send_buf,ev->send_len)) < 0)
				{
						int ssl_conn_err = SSL_get_error(ev->ssl,rtn);
						if (SSL_ERROR_WANT_WRITE == ssl_conn_err) 
						{
								continue;
						}
						LOG(ERROR)<<"ssl send failed,ip="<<ev->ip;
						return -1;
				}
				if(rtn == ev->send_len)
				{
						ev->flag = 2;
						//LOG(INFO)<<"ssl send success,ip="<<ev->ip<<",send_len="<<rtn;
						//LOG(INFO)<<"ssl send_buf=\n"<<ev->send_buf;
						return 0;
				}		
				LOG(ERROR)<<"ssl send failed,ip="<<ev->ip;
				return -1;
		}

		int ssl_conn_err = SSL_get_error(ev->ssl,ssl_conn_ret);
		if (SSL_ERROR_WANT_WRITE == ssl_conn_err||SSL_ERROR_WANT_READ == ssl_conn_err) 
		{
				ev->flag = 1;
				//LOG(INFO)<<"ssl connect continue,ip="<<ev->ip;
				return 0;
		}

		//LOG(INFO)<<"ssl connect failed,ip="<<ev->ip;
		return -1;
}

int ssl_first_connect_write(ev_t*ev)
{
		int rtn = 0;
		ev->ctx = SSL_CTX_new(SSLv23_client_method());
		if(ev->ctx == NULL)
		{
				LOG(ERROR)<<"ssl_ctx_new failed,ip="<<ev->ip;
				return -1;
		}

		ev->ssl = SSL_new(ev->ctx);
		if(ev->ssl == NULL)
		{
				LOG(ERROR)<<"ssl_new failed,ip="<<ev->ip;
				return -1;
		}

		SSL_set_mode(ev->ssl,SSL_MODE_ENABLE_PARTIAL_WRITE);
		SSL_set_fd(ev->ssl,ev->fd);

		rtn = ssl_connect_write(ev);
		return rtn;
}

int ssl_read(ev_t*ev)
{
		int size = 0,rtn = 0,status_code = 0;
		char*recv_buf = (char*)calloc(1,1024*1024);
		do
		{
				rtn = SSL_read(ev->ssl,recv_buf+size,1024);
				if(rtn < 0)
				{
						int ssl_conn_err = SSL_get_error(ev->ssl,rtn);
						if (SSL_ERROR_WANT_READ == ssl_conn_err) 
						{
								continue;
						}
						LOG(ERROR)<<"ssl recv failed,ip="<<ev->ip;
						free(recv_buf);
						return -1;
				}
				size += rtn;
		}
		while(rtn > 0 && size < 1024*1023);

		if(size > 0)
		{
				if(ev->type == DIAL_SMTP)
				{
						if(strstr(recv_buf,"220") || strstr(recv_buf,"250"))
						{
								free(recv_buf);
								return 0;
						}
						free(recv_buf);
						LOG(WARNING)<<"smtp ssl recv failed,ip="<<ev->ip;
						return -1;
				}

				int len = policy_map[ev->policy].option.expectMatch.size();
				if(len > 0)
				{
						if(!strstr(recv_buf,policy_map[ev->policy].option.expectMatch.c_str()))
						{
								free(recv_buf);
								//LOG(ERROR)<<"ssl str check error,ip="<<ev->ip;
								return -1;
						}
				}
				int code_num = policy_map[ev->policy].option.expectCode.size();
				if(code_num > 0)
				{
						int i = 0;
						int status_code = atoi(recv_buf+9);
						for(i = 0 ; i < code_num ; i++)
						{
								if(status_code == policy_map[ev->policy].option.expectCode[i])
								{
										break;
								}
						}
						if(i == code_num)
						{
								free(recv_buf);
								//LOG(WARNING)<<"ssl status_code check error,ip="<<ev->ip;
								return -1;
						}
				}
				free(recv_buf);
				//LOG(INFO)<<"ssl recv and check success,ip="<<ev->ip;
				return 0;
		}
		free(recv_buf);
		//LOG(WARNING)<<"ssl recv failed,ip="<<ev->ip<<"dial_type="<<ev->type;
		return -1;
}

void *https_epoll_thread(void* arg)
{
		struct epoll_event events[EVENT_SIZE];
		int fds = 0, i = 0,rtn = 0;

		while(true)
		{
				fds = epoll_wait(g_epoll_https_fd,events,EVENT_SIZE,-1);

				if(fds == -1 && errno == EINTR)
				{
						continue;
				}
				for(i = 0 ; i < fds ; i++)
				{
						ev_t* ev = (ev_t*)events[i].data.ptr;

						//LOG(INFO)<<"ssl ip="<<ev->ip<<",event="<<events[i].events<<",flag="<<ev->flag;
						
						if(events[i].events & EPOLLERR)
						{
								update_dial_result(ev,false);
								https_ev_del(ev);
						}
						else if(events[i].events == EPOLLOUT && 0 == ev->flag)
						{
								rtn = ssl_first_connect_write(ev);
								if(rtn < 0)
								{
										update_dial_result(ev,false);
										https_ev_del(ev);
								}
						}
						else if(events[i].events == (EPOLLOUT | EPOLLIN))
						{
								if(ev->flag == 1)
								{
										rtn = ssl_connect_write(ev);
										if(!rtn)
										{
												continue;
										}
										else
										{
												update_dial_result(ev,false);
										}
								}
								else if(ev->flag == 2)
								{
										rtn = ssl_read(ev);
										if(!rtn)
										{
												update_dial_result(ev,true);
										}
										else
										{
												update_dial_result(ev,false);
										}
								}
								https_ev_del(ev);
						}
				}
		}
}


