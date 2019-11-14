#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "log.h"
#include "http.h"
#include "tcp.h"
#include "common.h"
#include "work.h"
#include "smtp.h"


const char *http_get = 
"GET %s HTTP/1.1\r\n"
"Host: %s\r\n"
"User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0\r\n"
"Accept: */*\r\n"
"Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"\r\n";


const char *http_post = 
"POST %s HTTP/1.1\r\n"
"Host: %s\r\n"
"User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)\r\n"
"Accept: */*\r\n"
"Content-Type: %s\r\n"
"Content-Length: %d\r\n"
"\r\n"
"%s";


void fill_http_send_msg(char*p_start,bool https,int *port,char* path)
{
		char* p_port = NULL;
		char* p_path = NULL;
		char port_arr[8] = {'\0'};

		p_port = strchr(p_start,':');
		if(p_port)
		{
				p_port += 1;
				p_path = strchr(p_port,'/');
				if(p_path)
				{
						strncpy(port_arr,p_port,p_path - p_port);
						*port = atoi(port_arr);
						strcpy(path,p_path);
				}
				else
				{
						strcpy(port_arr,p_port);
						*port = atoi(port_arr);
						strcpy(path,"/");
				}
		}
		else
		{
				strcpy(path,"/");
				if(https)
				{
						*port = HTTPS_PORT;
				}
				else
				{
						*port = HTTP_PORT;
				}		
		}
}

void change_str_content(char*content,char* buf,short policy_method) 
{
		char* p = NULL;
		char* content_start = content;
		const char* s = "\\r\\n";
		const char* br = "\\r\\n\\r\\n";
		const char* enter = "\r\n";
		do   
		{           
				p = strstr(content,s);
				if(p)
				{           
						strncat(buf,content,p-content);
						strcat(buf,enter);
						content = p+4;
				}    
		}        
		while(p);
		strcat(buf,content);

		if(policy_method == DIAL_HTTPCOMMON && !strstr(content_start,br))
		{
				strcat(buf,enter);
				strcat(buf,enter);
		}
}

int parse_http_policy_arg(ev_t* ev,const char* policy,int* port,bool* https,enum policy_type type)
{
		char tmp_buf[4096] = {'\0'};
		char buf[4096] = {'\0'};

		if(DIAL_EXTTCPPORT == type)
		{
				strcpy(tmp_buf,policy_map[policy].option.testMethod.c_str());	
				change_str_content(tmp_buf,buf,type);
				strcpy(ev->send_buf,buf);
				ev->send_len = strlen(ev->send_buf);
				*port = policy_map[policy].port;
				return 0;
		}

		char path[256] = {'\0'};
		char url[1024] = {'\0'};
		strcpy(url,policy_map[policy].option.destUrl.c_str());
		char* p_start = url;

		if(strstr(url,"https://"))
		{
				*https = true;
				p_start += strlen("https://");
				fill_http_send_msg(p_start,*https,port,path);
				if(DIAL_EXTHTTPGET == type)
				{
						sprintf(ev->send_buf,http_get,path,ev->ip);
				}
				else if(DIAL_EXTHTTPPOST == type)
				{
						sprintf(ev->send_buf,http_post,path,ev->ip,policy_map[policy].option.contentType.c_str(),
						policy_map[policy].option.testMethod.size(),policy_map[policy].option.testMethod.c_str());
				}
				else if(DIAL_HTTPCOMMON == type)
				{
						strcpy(tmp_buf,policy_map[policy].option.testMethod.c_str());	
						change_str_content(tmp_buf,buf,type);
						strcpy(ev->send_buf,buf);
				}
				ev->send_len = strlen(ev->send_buf);
		}
		else if(strstr(url,"http://"))
		{
				*https = false;
				p_start += strlen("http://");
				fill_http_send_msg(p_start,*https,port,path);
				if(DIAL_EXTHTTPGET == type)
				{
						sprintf(ev->send_buf,http_get,path,ev->ip);
				}
				else if(DIAL_EXTHTTPPOST == type)
				{
						sprintf(ev->send_buf,http_post,path,ev->ip,policy_map[policy].option.contentType.c_str(),
						policy_map[policy].option.testMethod.size(),policy_map[policy].option.testMethod.c_str());
				}
				else if(DIAL_HTTPCOMMON == type)
				{
						strcpy(tmp_buf,policy_map[policy].option.testMethod.c_str());	
						change_str_content(tmp_buf,buf,type);
						strcpy(ev->send_buf,buf);
				}
				ev->send_len = strlen(ev->send_buf);
		}
		else
		{
				return -1;
		}

		return 0;
}

int create_http_send_arg(ev_t* ev,const char* policy,int* port,bool* https)
{
		int rtn = 0;

		switch(ev->type)
		{
				case DIAL_HTTPGET:
				{
						sprintf(ev->send_buf,http_get,"/",ev->ip);
						ev->send_len = strlen(ev->send_buf);
						*port = HTTP_PORT;
						*https = false;
						break;
				}
				case DIAL_EXTHTTPGET:
				{
						rtn = parse_http_policy_arg(ev,policy,port,https,DIAL_EXTHTTPGET);
						break;
				}
				case DIAL_EXTHTTPPOST:
				{
						rtn = parse_http_policy_arg(ev,policy,port,https,DIAL_EXTHTTPPOST);
						break;
				}
				case DIAL_HTTPCOMMON:
				{
						rtn = parse_http_policy_arg(ev,policy,port,https,DIAL_HTTPCOMMON);
						break;
				}
				case DIAL_EXTTCPPORT:
				{
						rtn = parse_http_policy_arg(ev,policy,port,https,DIAL_EXTTCPPORT);
						break;
				}
				case DIAL_SMTP:
				{
						strcpy(ev->send_buf,SMTP_MSG);
						ev->send_len = strlen(ev->send_buf);
						*port = policy_map[policy].port;
						*https = true;
						break;
				}
				
		}

		return rtn;
}

void handle_http_task(const char*ip,const char*policy,enum policy_type type)
{
		bool is_ipv6 = false;
		if(strstr(ip,"::"))
		{
				is_ipv6 = true;
		}
		int fd = new_unblock_tcp_socket(is_ipv6);
		if(fd < 0)
		{
				LOG(WARNING)<<"create unblock tcp fd failed";
				exit_process();
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

		int port = 0;
		bool https = false;
		if(create_http_send_arg(my_ev,policy,&port,&https) < 0)
		{
				close(fd);
				free(my_ev);
				LOG(ERROR)<<"create http send arg failed,ip="<<ip;
				return;
		}
		gettimeofday(&my_ev->t_start,NULL);

		if(https)
		{
				if(https_epoll_add(fd,my_ev) < 0)
				{
						LOG(ERROR)<<"add https ev fd failed,ip="<<ip;
						https_ev_del(my_ev);
						return;
				}
		}
		else
		{
				if(tcp_epoll_add(fd,my_ev) < 0)
				{
						LOG(ERROR)<<"add http ev fd failed,ip="<<ip;
						tcp_ev_del(my_ev);
						return;
				}
		}

		connect_server(is_ipv6,ip,port,fd);
}





