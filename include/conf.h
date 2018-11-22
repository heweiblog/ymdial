#ifndef _CONF_H_
#define _CONF_H_

#include "inifile.h"

#define CONF_FILE "/etc/ymdial.ini"

typedef struct config
{
	int dial_port;
	int agent_port;
	int health;
	int delay_weight;
	int lost_weight;
	int count;
	int timeout;
	int interval;
	char dname[32];	
	char agent_ip[32];

}cfg_t; 

void load_config();


#endif
