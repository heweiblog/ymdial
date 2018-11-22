#ifndef _HTTP_H_
#define _HTTP_H_

#include "epoll.h"

//void handle_http_task(const char* ip,const char* policy);

#define HTTP_PORT 80
#define HTTPS_PORT 443

void handle_http_task(const char*ip,const char* policy,enum policy_type type);

void handle_exthttp_task(const char*ip,const char* policy,enum policy_type type);

#endif
