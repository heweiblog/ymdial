#ifndef _LOG_H_
#define _LOG_H_

#include "glog/logging.h"


void init_log(bool debug,char**argv);

void log_destroy();

#endif
