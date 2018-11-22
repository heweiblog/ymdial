#include "log.h"
#include "conf.h"
#include "main.h"
#include "server.h"
#include "work.h"


int main(int argc,char** argv)
{
		bool debug = parse_arg(argc,argv);
		init_log(debug,argv);
		load_config();

		process_init();
		init_thread();

		thrift_client_init(cfg.agent_ip,cfg.agent_port);
		thrift_server_init(cfg.dial_port);
		
		log_destroy();
		return 0;
}



