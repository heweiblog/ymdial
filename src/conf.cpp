#include <string.h>
#include "conf.h"
#include "log.h"
#include "common.h"

cfg_t cfg;

void load_config()
{
		int ret = 0;
		inifile::IniFile cfg_ini;

		if(cfg_ini.load(CONF_FILE) < 0)
		{
				LOG(WARNING)<<"load conf file "<<CONF_FILE<<" fialed";
				exit_process();
		}

		cfg.dial_port = cfg_ini.getIntValue("dial","port",ret);
		if(ret < 0)
		{
				LOG(ERROR)<<"read conf file fialed";
		}
		LOG(INFO)<<"dial_port="<<cfg.dial_port;

		cfg.agent_port = cfg_ini.getIntValue("agent","port",ret);
		if(ret < 0)
		{
				LOG(ERROR)<<"read conf file fialed";
		}
		LOG(INFO)<<"agent_port="<<cfg.agent_port;

		strcpy(cfg.agent_ip,cfg_ini.getStringValue("agent","ip",ret).c_str());
		if(ret < 0)
		{
				LOG(ERROR)<<"read conf file fialed";
		}
		LOG(INFO)<<"agent_ip="<<cfg.agent_ip;

		cfg.health = cfg_ini.getIntValue("server","health",ret);
		if(ret < 0)
		{
				LOG(ERROR)<<"read conf file fialed";
		}
		LOG(INFO)<<"health_value="<<cfg.health;

		cfg.delay_weight = cfg_ini.getIntValue("server","delay_weight",ret);
		if(ret < 0)
		{
				LOG(ERROR)<<"read conf file fialed";
		}
		LOG(INFO)<<"delay_weight="<<cfg.delay_weight;

		cfg.lost_weight = cfg_ini.getIntValue("server","lost_weight",ret);
		if(ret < 0)
		{
				LOG(ERROR)<<"read conf file fialed";
		}
		LOG(INFO)<<"lost_weight="<<cfg.lost_weight;

		cfg.count = cfg_ini.getIntValue("server","count",ret);
		if(ret < 0)
		{
				LOG(ERROR)<<"read conf file fialed";
		}
		LOG(INFO)<<"dig_count="<<cfg.count;

		cfg.timeout = cfg_ini.getIntValue("server","timeout",ret);
		if(ret < 0)
		{
				LOG(ERROR)<<"read conf file fialed";
		}
		LOG(INFO)<<"dig_timeout="<<cfg.timeout;

		cfg.interval = cfg_ini.getIntValue("server","interval",ret);
		if(ret < 0)
		{
				LOG(ERROR)<<"read conf file fialed";
		}
		LOG(INFO)<<"dig_interval="<<cfg.interval;

		strcpy(cfg.dname,cfg_ini.getStringValue("server","dname",ret).c_str());
		if(ret < 0)
		{
				LOG(ERROR)<<"read conf file fialed";
		}
		LOG(INFO)<<"dig_dname="<<cfg.dname;
}
