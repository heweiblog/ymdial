#ifndef _ICMP_H_
#define _ICMP_H_

#include <netinet/ip_icmp.h>

#define ICMP_DATA_LEN 20
#define ICMP_BUFF_LEN 128


int create_raw_fd();
uint32_t cal_mask(int val);
unsigned short calc_icmp_chksum(const void *pPacket, int iPktLen);
int new_icmp_echo(const int iPacketNum, unsigned char *aucSendBuf,const int iDataLen);
int init_icmp();

void handle_icmp_task(const char* ip);

void *icmp_recv_thread(void*arg);
void *icmp_check_thread(void*arg);
void* ipsec_work_thread(void * arg);

#endif
