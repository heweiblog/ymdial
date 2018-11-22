#ifndef _DIAL_SERVER_H_
#define _DIAL_SERVER_H_

#include "conf.h"
#include "work.h"

extern cfg_t cfg;

extern vector<DialServerResult> server_results;

extern const char *http_get;

void * server_dial_thread(void* arg);

#endif
