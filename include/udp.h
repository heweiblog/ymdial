#ifndef __UDP_H__
#define __UDP_H__

#include "common.h"

extern unsigned char *aucSendBuf;
extern int iPktLen;

void handle_udp_port_task(const char*ip,const int port,const char*policy,enum policy_type type);

void* udp_dial_thread(void*arg);

#endif
