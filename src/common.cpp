#include <stdio.h>
#include "version.h"
#include "log.h"
#include "common.h"
#include "clib/daemon.h"


void exit_process()
{
		LOG(WARNING)<<"Stop YmDial Module...";
		daemon_stop();
		exit(0);
}

void check_port()
{
		FILE* fp = popen("pidof edns_dial","r");
		if(NULL == fp)
		{       
				printf("popen(pidof edns_dial) error\n");
				exit(0);
		}
		char cmd[128] = {'\0'};
		int len = fread(cmd,128,1,fp);
		int str_len = strlen(cmd);
		if(str_len <= 0)
		{
				pclose(fp);
				return;
		}

		printf("please after kill edns_dial and start ymdial...\n");
		pclose(fp);
		exit(0);

		#if 0
		int pid1 = 0,pid2 = 0;
		sscanf(cmd,"%d %d\n",&pid1,&pid2);
		pclose(fp);

		memset(cmd,0,128);
		sprintf(cmd,"kill -9 %d",pid1);
		fp = popen(cmd,"r");
		if(NULL == fp)
		{
				printf("kill -9 %d error",pid1);
				exit(0);
		}

		memset(cmd,0,128);
		sprintf(cmd,"kill -9 %d",pid2);
		fp = popen(cmd,"r");
		if(NULL == fp)
		{
				printf("kill -9 %d error",pid2);
				exit(0);
		}
		pclose(fp);
		printf("kill edns_dial success\n");
		#endif
}

bool parse_arg(int argc,char** argv)
{
		check_port();

		if(argc == 2)
		{
				if(!strcmp("start",argv[1]))
				{
						daemon_start(1);
						return false;
				}
				else if(!strcmp("stop",argv[1]))
				{
						daemon_stop();
						exit(0);
				}
				else if(!strcmp("restart",argv[1]))
				{
						daemon_stop();
						daemon_start(1);
						return false;
				}
				else if(!strcmp("-d",argv[1]))
				{
						return true;
				}
				else if(!strcmp("-v",argv[1]) && argc == 2)
				{
						printf("%s:%s\n",argv[0],VERSION);
						exit(0);
				}
		}

		printf("error parameter:please use:\n%s start|restart|stop\n%s -d\n%s -v\n",argv[0],argv[0],argv[0]);
		exit(0);
}


