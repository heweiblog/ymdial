#ifndef __COMMON_H__
#define __COMMON_H__

enum policy_type 
{
		DIAL_TCPPORT = 0,
		DIAL_ICMP = 1,
		DIAL_HTTPGET = 2,
		DIAL_DATABASE = 3,
		DIAL_EXTHTTPGET = 4,
		DIAL_EXTTCPPORT = 5,
		DIAL_EXTHTTPPOST = 6,
		DIAL_HTTPCOMMON = 7,
		DIAL_UDPPORT = 8,
		DIAL_FTP = 9,
		DIAL_SMTP = 10,
		DIAL_SNMP = 11,
		DIAL_ORACLE = 12,
};


enum dial_type 
{
		AUTH = 1,		// Monitoring of authorization records
		SERVER = 2,		
		URL = 3,
		DC = 4,
};


#define SUB_TIME(x,y)  ((x.tv_sec * 1000*1000 + x.tv_usec) - (y.tv_sec * 1000*1000 + y.tv_usec))

void exit_process();

bool parse_arg(int argc,char** argv);

#endif
