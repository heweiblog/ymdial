#include <pthread.h>
#include <arpa/inet.h>
#include "log.h"
#include "server.h"
#include "mysql.h"
#include "epoll.h"
#include "snmp.h"
#include "icmp.h"

bool dial_status = false;
bool register_status = false;
pthread_mutex_t client_lock;

map<string,HealthPolicyInfo> policy_map;

map<string,dial_node_t> dial_map;
pthread_rwlock_t dial_map_lock;

map<string,server_node_t> server_map;
pthread_rwlock_t server_map_lock;

map<string,ip_node_t> ip_map;
pthread_rwlock_t ip_map_lock;

map<string,snmp_node_t> snmp_map;
map<string,ipsec_node_t> ipsec_map;

queue<ev_t*> common_queue;
pthread_mutex_t common_queue_lock;

queue<ev_t*> udp_queue;
pthread_mutex_t udp_queue_lock;

queue<ev_t*> snmp_queue;
pthread_mutex_t snmp_queue_lock;

set<string> ping_set;
pthread_mutex_t ping_set_lock;

boost::shared_ptr<TTransport> transport_client;  
boost::shared_ptr<TProtocol> protocol_client;

RetCode::type DialHandler:: systemCommand(const SysCommand::type cmdType)
{
		return RetCode::OK;
}

RetCode::type DialHandler:: addHealthPolicy(const HealthPolicyInfo& policy)
{
		policy_map[policy.name] = policy;
		LOG(INFO)<<"ADD_CONF:add policy success:"<<"id="<<policy.name<<",method="<<policy.method<<",port="<<policy.port<<",freq="<<policy.freq<<",policy_count="<<policy_map.size(); 
		LOG(INFO)<<"destUrl="<<policy.option.destUrl; 
		LOG(INFO)<<"testMethod="<<policy.option.testMethod; 
		LOG(INFO)<<"expectMatch="<<policy.option.expectMatch; 
		LOG(INFO)<<"contentType="<<policy.option.contentType; 
		return RetCode::OK;
}

RetCode::type DialHandler:: modHealthPolicy(const HealthPolicyInfo& policy)
{
		policy_map[policy.name] = policy;
		LOG(INFO)<<"MOD_CONF:mod policy success:"<<"id="<<policy.name<<",method="<<policy.method; 
		return RetCode::OK;
}

RetCode::type DialHandler:: delHealthPolicy(const HealthPolicyInfo& policy)
{
		policy_map.erase(policy.name);
		LOG(INFO)<<"DEL_CONF:del policy success:"<<"id="<<policy.name; 
		return RetCode::OK;
}

RetCode::type DialHandler:: addHealthGroup(const std::string& groupName, const std::string& policyName)
{
		map<string,dial_node_t>::iterator iter = dial_map.find(groupName);

		if(iter == dial_map.end())
		{
				dial_node_t dial_node;
				dial_node.type = AUTH; 
				dial_node.policy.push_back(policyName);

				pthread_rwlock_wrlock(&dial_map_lock);
				dial_map[groupName] = dial_node;
				pthread_rwlock_unlock(&dial_map_lock);
				LOG(INFO)<<"ADD_CONF:add a new auth group success:group="<<groupName<<",policy="<<policyName; 
				return RetCode::OK;
		}

		ip_policy_result_t ip_policy_result;
		ip_policy_result.policyname = policyName;
		ip_policy_result.dial_flag = false;
		ip_policy_result.count = 1;
		ip_policy_result.delay = 0;
		ip_policy_result.status = DialStatus::FAIL;

		vector<DialRecord>::iterator auth_iter;
		vector<ip_policy_result_t>::iterator result_iter;

		for(auth_iter = iter->second.auth.begin() ; auth_iter != iter->second.auth.end() ; auth_iter++)
		{
				for(result_iter = ip_map[auth_iter->ip.addr].ip_policy_result.begin() ; result_iter != ip_map[auth_iter->ip.addr].ip_policy_result.end() ; result_iter++)
				{
						if(policyName == result_iter->policyname)
						{
								pthread_mutex_lock(&ip_map[auth_iter->ip.addr].mutex);
								result_iter->count++;
								pthread_mutex_unlock(&ip_map[auth_iter->ip.addr].mutex);
								LOG(INFO)<<"ADD_CONF:add policy to ip success:ip="<<auth_iter->ip.addr<<",policy="<<policyName<<",count="<<result_iter->count; 
								break;
						}
				}
				if(result_iter == ip_map[auth_iter->ip.addr].ip_policy_result.end())
				{
						pthread_mutex_lock(&ip_map[auth_iter->ip.addr].mutex);
						ip_map[auth_iter->ip.addr].ip_policy_result.push_back(ip_policy_result);
						pthread_mutex_unlock(&ip_map[auth_iter->ip.addr].mutex);
						LOG(INFO)<<"ADD_CONF:add a new policy to ip success:ip="<<auth_iter->ip.addr<<",policy="<<policyName<<",count="<<result_iter->count; 
				}
		}

		pthread_rwlock_wrlock(&dial_map_lock);
		iter->second.policy.push_back(policyName);
		pthread_rwlock_unlock(&dial_map_lock);
		
		LOG(INFO)<<"ADD_CONF:add a policy to auth group success:group="<<groupName<<",policy="<<policyName; 
		return RetCode::OK;
}

RetCode::type DialHandler:: delHealthGroup(const std::string& groupName, const std::string& policyName)
{
		map<string,dial_node_t>::iterator iter = dial_map.find(groupName);

		if(iter == dial_map.end())
		{
				LOG(INFO)<<"DEL_CONF:del a policy from auth group failed:group="<<groupName<<",policy="<<policyName; 
				return RetCode::FAIL;
		}
		
		vector<DialRecord>::iterator auth_iter;
		vector<ip_policy_result_t>::iterator result_iter;

		for(auth_iter = iter->second.auth.begin() ; auth_iter != iter->second.auth.end() ; auth_iter++)
		{
				for(result_iter = ip_map[auth_iter->ip.addr].ip_policy_result.begin() ; result_iter != ip_map[auth_iter->ip.addr].ip_policy_result.end() ; result_iter++)
				{
						if(policyName == result_iter->policyname)
						{
								pthread_mutex_lock(&ip_map[auth_iter->ip.addr].mutex);
								result_iter->count--;
								LOG(INFO)<<"DEL_CONF:del a policy from ip success:ip="<<auth_iter->ip.addr<<",policy="<<policyName<<",count="<<result_iter->count; 
								if(0 == result_iter->count)
								{
										LOG(INFO)<<"DEL_CONF:del all policy cite from ip success:ip="<<auth_iter->ip.addr<<",policy="<<policyName<<",count="<<result_iter->count; 
										ip_map[auth_iter->ip.addr].ip_policy_result.erase(result_iter);
								}
								pthread_mutex_unlock(&ip_map[auth_iter->ip.addr].mutex);
								break;
						}
				}
		}

		vector<string>::iterator policy_iter;

		for(policy_iter = iter->second.policy.begin() ; policy_iter != iter->second.policy.end() ; policy_iter++)
		{
				if(policyName == *policy_iter)
				{
						pthread_rwlock_wrlock(&dial_map_lock);
						LOG(INFO)<<"DEL_CONF:del a policy from auth group success:group="<<groupName<<",policy="<<policyName; 
						iter->second.policy.erase(policy_iter);
						if(0 == iter->second.policy.size())
						{
								LOG(INFO)<<"DEL_CONF:del auth group success:group="<<groupName; 
								dial_map.erase(iter);
						}
						pthread_rwlock_unlock(&dial_map_lock);
						break;
				}
		}

		return RetCode::OK;
}

RetCode::type DialHandler:: addHealthRecord(const std::string& groupName, const std::vector<DialRecord> & records)
{
		map<string,dial_node_t>::iterator iter = dial_map.find(groupName);

		if(iter == dial_map.end())
		{
				LOG(INFO)<<"ADD_CONF:add auth record failed,group not exist:group="<<groupName; 
				return RetCode::FAIL;
		}
		
		ip_node_t ip_node;
		pthread_mutex_init(&ip_node.mutex,NULL);
		ip_policy_result_t ip_policy_result;
		ip_policy_result.dial_flag = false;
		ip_policy_result.count = 1;
		ip_policy_result.delay = 0;
		ip_policy_result.status = DialStatus::FAIL;

		vector<string>::iterator policy_iter;

		for(policy_iter = iter->second.policy.begin() ; policy_iter != iter->second.policy.end() ; policy_iter++)
		{
				ip_policy_result.policyname = *policy_iter;
				ip_node.ip_policy_result.push_back(ip_policy_result);
		}

		uint32_t i = 0,j = 0;
		map<string,ip_node_t>::iterator ip_iter;
		vector<ip_policy_result_t>::iterator result_iter;

		for(i = 0 ; i < records.size() ; i++)
		{
				ip_iter = ip_map.find(records[i].ip.addr);	
				if(ip_iter == ip_map.end())
				{
						pthread_rwlock_wrlock(&ip_map_lock);
						ip_map[records[i].ip.addr] = ip_node;
						pthread_rwlock_unlock(&ip_map_lock);
						LOG(INFO)<<"ADD_CONF:add a new ip success:ip="<<records[i].ip.addr<<",policy_num="<<iter->second.policy.size(); 
				}
				else
				{
						for(policy_iter = iter->second.policy.begin() ; policy_iter != iter->second.policy.end() ; policy_iter++)
						{
								for(j = 0 ; j < ip_iter->second.ip_policy_result.size() ; j++)
								{
										if(ip_iter->second.ip_policy_result[j].policyname == *policy_iter)
										{
												pthread_mutex_lock(&ip_iter->second.mutex);
												ip_iter->second.ip_policy_result[j].count++;
												pthread_mutex_unlock(&ip_iter->second.mutex);
												LOG(INFO)<<"ADD_CONF:add a policy to ip success:ip="<<records[i].ip.addr<<",policy="<<*policy_iter<<",count="<<ip_iter->second.ip_policy_result[j].count; 
												break;
										}
								}
								if(j == ip_iter->second.ip_policy_result.size())
								{
										ip_policy_result.policyname = *policy_iter;
										pthread_mutex_lock(&ip_iter->second.mutex);
										ip_iter->second.ip_policy_result.push_back(ip_policy_result);
										pthread_mutex_unlock(&ip_iter->second.mutex);
										LOG(INFO)<<"ADD_CONF:add a new policy to ip success:ip="<<records[i].ip.addr<<",policy="<<*policy_iter<<",count="<<ip_iter->second.ip_policy_result[j].count; 
								}
						}
				}

				pthread_rwlock_wrlock(&dial_map_lock);
				iter->second.auth.push_back(records[i]);
				pthread_rwlock_unlock(&dial_map_lock);
				LOG(INFO)<<"ADD_CONF:add auth_record to auth_group success:group="<<groupName<<",rid="<<records[i].rid<<",ip="<<records[i].ip.addr; 
		}

		return RetCode::OK;
}

RetCode::type DialHandler:: delHealthRecord(const std::string& groupName, const std::vector<DialRecord> & records)
{
		map<string,dial_node_t>::iterator iter = dial_map.find(groupName);

		if(iter == dial_map.end())
		{
				LOG(INFO)<<"DEL_CONF:del auth record failed,group not exist:group="<<groupName; 
				return RetCode::FAIL;
		}
		
		uint32_t i = 0;
		vector<string>::iterator policy_iter;
		map<string,ip_node_t>::iterator ip_iter;
		vector<ip_policy_result_t>::iterator result_iter;
		vector<DialRecord>::iterator auth_iter;

		for(i = 0 ; i < records.size() ; i++)
		{
				ip_iter = ip_map.find(records[i].ip.addr);	
				if(ip_iter == ip_map.end())
				{
						LOG(INFO)<<"DEL_CONF:del ip from ip_map failed :ip="<<records[i].ip.addr<<",rid="<<records[i].rid; 
				}
				else
				{
						for(policy_iter = iter->second.policy.begin() ; policy_iter != iter->second.policy.end() ; policy_iter++)
						{
								for(result_iter = ip_map[records[i].ip.addr].ip_policy_result.begin() ; result_iter != ip_map[records[i].ip.addr].ip_policy_result.end() ; result_iter++)
								{
										if(*policy_iter == result_iter->policyname)
										{
												pthread_mutex_lock(&ip_map[records[i].ip.addr].mutex);
												result_iter->count--;
												LOG(INFO)<<"DEL_CONF:del a policy from ip_map success:ip="<<records[i].ip.addr<<",policy="<<*policy_iter<<",count="<<result_iter->count; 
												if(0 == result_iter->count)
												{
														LOG(INFO)<<"DEL_CONF:del all policy cite from ip_map success:ip="<<records[i].ip.addr<<",policy="<<*policy_iter<<",count="<<result_iter->count; 
														ip_map[records[i].ip.addr].ip_policy_result.erase(result_iter);
												}
												pthread_mutex_unlock(&ip_map[records[i].ip.addr].mutex);
												break;
										}
								}

						}
				}

				for(auth_iter = iter->second.auth.begin() ; auth_iter != iter->second.auth.end() ; auth_iter++)
				{
						if(auth_iter->rid == records[i].rid)
						{
								pthread_rwlock_wrlock(&dial_map_lock);
								iter->second.auth.erase(auth_iter);
								pthread_rwlock_unlock(&dial_map_lock);
								LOG(INFO)<<"DEL_CONF:del record from auth_group success:ip="<<records[i].ip.addr<<",rid="<<records[i].rid<<",group="<<iter->first;
								break;
						}
				}
		}

		LOG(INFO)<<"DEL_CONF:del records from auth_group success:record_size="<<records.size()<<",group="<<iter->first; 
		return RetCode::OK;
}


string get_url_addr(const char* url)
{
		char addr[30] = {'\0'};
		char* p_s = (char*)strstr(url,"://");
		p_s += 3;
		char* p_e = strchr(p_s,':');
		strncpy(addr,p_s,p_e-p_s);
		string ip(addr);
		return ip;
}

RetCode::type DialHandler:: addNginxGroup(const std::string& groupName, const std::string& policyName)
{
		map<string,dial_node_t>::iterator iter = dial_map.find(groupName);

		if(iter == dial_map.end())
		{
				dial_node_t dial_node;
				dial_node.type = URL; 
				dial_node.policy.push_back(policyName);

				pthread_rwlock_wrlock(&dial_map_lock);
				dial_map[groupName] = dial_node;
				pthread_rwlock_unlock(&dial_map_lock);

				LOG(INFO)<<"ADD_CONF:add a new url group success:group="<<groupName<<",policy="<<policyName; 
				return RetCode::OK;
		}

		ip_policy_result_t ip_policy_result;
		ip_policy_result.policyname = policyName;
		ip_policy_result.dial_flag = false;
		ip_policy_result.count = 1;
		ip_policy_result.delay = 0;
		ip_policy_result.status = DialStatus::FAIL;

		vector<DialNginxServer>::iterator url_iter;
		vector<ip_policy_result_t>::iterator result_iter;
		string addr;

		for(url_iter = iter->second.url.begin() ; url_iter != iter->second.url.end() ; url_iter++)
		{
				addr = get_url_addr(url_iter->localURL.c_str());

				for(result_iter = ip_map[addr].ip_policy_result.begin() ; result_iter != ip_map[addr].ip_policy_result.end() ; result_iter++)
				{
						if(policyName == result_iter->policyname)
						{
								pthread_mutex_lock(&ip_map[addr].mutex);
								result_iter->count++;
								pthread_mutex_unlock(&ip_map[addr].mutex);

								LOG(INFO)<<"ADD_CONF:add policy to ip success:ip="<<addr<<",policy="<<policyName<<",count="<<result_iter->count; 
								break;
						}
				}
				if(result_iter == ip_map[addr].ip_policy_result.end())
				{
						pthread_mutex_lock(&ip_map[addr].mutex);
						ip_map[addr].ip_policy_result.push_back(ip_policy_result);
						pthread_mutex_unlock(&ip_map[addr].mutex);

						LOG(INFO)<<"ADD_CONF:add a new policy to ip success:ip="<<addr<<",policy="<<policyName<<",count="<<result_iter->count; 
				}
		}

		pthread_rwlock_wrlock(&dial_map_lock);
		iter->second.policy.push_back(policyName);
		pthread_rwlock_unlock(&dial_map_lock);
		
		LOG(INFO)<<"ADD_CONF:add a policy to url group success:group="<<groupName<<",policy="<<policyName; 
		return RetCode::OK;
}

RetCode::type DialHandler:: delNginxGroup(const std::string& groupName, const std::string& policyName)
{
		map<string,dial_node_t>::iterator iter = dial_map.find(groupName);

		if(iter == dial_map.end())
		{
				LOG(INFO)<<"DEL_CONF:del a policy url auth group failed:group="<<groupName<<",policy="<<policyName; 
				return RetCode::FAIL;
		}
		
		vector<DialNginxServer>::iterator url_iter;
		vector<ip_policy_result_t>::iterator result_iter;
		string addr;

		for(url_iter = iter->second.url.begin() ; url_iter != iter->second.url.end() ; url_iter++)
		{
				addr = get_url_addr(url_iter->localURL.c_str());

				for(result_iter = ip_map[addr].ip_policy_result.begin() ; result_iter != ip_map[addr].ip_policy_result.end() ; result_iter++)
				{
						if(policyName == result_iter->policyname)
						{
								pthread_mutex_lock(&ip_map[addr].mutex);
								result_iter->count--;
								LOG(INFO)<<"DEL_CONF:del a policy from ip success:ip="<<addr<<",policy="<<policyName<<",count="<<result_iter->count; 
								if(0 == result_iter->count)
								{
										LOG(INFO)<<"DEL_CONF:del all policy cite from ip success:ip="<<addr<<",policy="<<policyName<<",count="<<result_iter->count; 
										ip_map[addr].ip_policy_result.erase(result_iter);
								}
								pthread_mutex_unlock(&ip_map[addr].mutex);
								break;
						}
				}
		}

		vector<string>::iterator policy_iter;

		for(policy_iter = iter->second.policy.begin() ; policy_iter != iter->second.policy.end() ; policy_iter++)
		{
				if(policyName == *policy_iter)
				{
						pthread_rwlock_wrlock(&dial_map_lock);
						iter->second.policy.erase(policy_iter);
						LOG(INFO)<<"DEL_CONF:del a policy from url group success:group="<<groupName<<",policy="<<policyName; 
						if(0 == iter->second.policy.size())
						{
								LOG(INFO)<<"DEL_CONF:del url group success:group="<<groupName; 
								dial_map.erase(iter);
						}
						pthread_rwlock_unlock(&dial_map_lock);
						break;
				}
		}

		return RetCode::OK;
}

RetCode::type DialHandler:: addNginxServer(const std::string& groupName, const std::vector<DialNginxServer> & servers)
{
		map<string,dial_node_t>::iterator iter = dial_map.find(groupName);

		if(iter == dial_map.end())
		{
				return RetCode::FAIL;
		}
		
		ip_node_t ip_node;
		pthread_mutex_init(&ip_node.mutex,NULL);
		ip_policy_result_t ip_policy_result;
		ip_policy_result.dial_flag = false;
		ip_policy_result.count = 1;
		ip_policy_result.delay = 0;
		ip_policy_result.status = DialStatus::FAIL;

		vector<string>::iterator policy_iter;

		for(policy_iter = iter->second.policy.begin() ; policy_iter != iter->second.policy.end() ; policy_iter++)
		{
				ip_policy_result.policyname = *policy_iter;
				ip_node.ip_policy_result.push_back(ip_policy_result);
		}

		uint32_t i = 0,j = 0;
		map<string,ip_node_t>::iterator ip_iter;
		vector<ip_policy_result_t>::iterator result_iter;
		string addr;

		for(i = 0 ; i < servers.size() ; i++)
		{
				addr = get_url_addr(servers[i].localURL.c_str());

				ip_iter = ip_map.find(addr);	
				if(ip_iter == ip_map.end())
				{
						pthread_rwlock_wrlock(&ip_map_lock);
						ip_map[addr] = ip_node;
						pthread_rwlock_unlock(&ip_map_lock);
						LOG(INFO)<<"ADD_CONF:add a new ip success:ip="<<addr<<",policy_num="<<iter->second.policy.size(); 
				}
				else
				{
						for(policy_iter = iter->second.policy.begin() ; policy_iter != iter->second.policy.end() ; policy_iter++)
						{
								for(j = 0 ; j < ip_iter->second.ip_policy_result.size() ; j++)
								{
										if(ip_iter->second.ip_policy_result[j].policyname == *policy_iter)
										{
												pthread_mutex_lock(&ip_iter->second.mutex);
												ip_iter->second.ip_policy_result[j].count++;
												pthread_mutex_unlock(&ip_iter->second.mutex);
												LOG(INFO)<<"ADD_CONF:add a policy to ip success:ip="<<addr<<",policy="<<*policy_iter<<",count="<<ip_iter->second.ip_policy_result[j].count; 
												break;
										}
								}
								if(j == ip_iter->second.ip_policy_result.size())
								{
										ip_policy_result.policyname = *policy_iter;
										pthread_mutex_lock(&ip_iter->second.mutex);
										ip_iter->second.ip_policy_result.push_back(ip_policy_result);
										pthread_mutex_unlock(&ip_iter->second.mutex);
										LOG(INFO)<<"ADD_CONF:add a new policy to ip success:ip="<<addr<<",policy="<<*policy_iter<<",count="<<ip_iter->second.ip_policy_result[j].count; 
								}
						}
				}

				pthread_rwlock_wrlock(&dial_map_lock);
				iter->second.url.push_back(servers[i]);
				pthread_rwlock_unlock(&dial_map_lock);

				LOG(INFO)<<"ADD_CONF:add url_server to url_group success:group="<<groupName<<",url="<<servers[i].localURL; 
		}

		return RetCode::OK;
}

RetCode::type DialHandler:: delNginxServer(const std::string& groupName, const std::vector<DialNginxServer> & servers)
{
		map<string,dial_node_t>::iterator iter = dial_map.find(groupName);

		if(iter == dial_map.end())
		{
				LOG(INFO)<<"DEL_CONF:del url failed,group not exist:group="<<groupName; 
				return RetCode::FAIL;
		}
		
		uint32_t i = 0,j = 0;
		vector<string>::iterator policy_iter;
		map<string,ip_node_t>::iterator ip_iter;
		vector<ip_policy_result_t>::iterator result_iter;
		vector<DialNginxServer>::iterator url_iter;
		string addr;

		for(i = 0 ; i < servers.size() ; i++)
		{
				addr = get_url_addr(servers[i].localURL.c_str());

				ip_iter = ip_map.find(addr);	
				if(ip_iter == ip_map.end())
				{
						LOG(INFO)<<"DEL_CONF:del ip from ip_map failed :ip="<<addr<<",url="<<servers[i].localURL; 
				}
				else
				{
						for(policy_iter = iter->second.policy.begin() ; policy_iter != iter->second.policy.end() ; policy_iter++)
						{
								for(result_iter = ip_map[addr].ip_policy_result.begin() ; result_iter != ip_map[addr].ip_policy_result.end() ; result_iter++)
								{
										if(*policy_iter == result_iter->policyname)
										{
												pthread_mutex_lock(&ip_map[addr].mutex);
												result_iter->count--;
												LOG(INFO)<<"DEL_CONF:del a policy from ip_map success:ip="<<addr<<",policy="<<*policy_iter<<",count="<<result_iter->count; 
												if(0 == result_iter->count)
												{
														LOG(INFO)<<"DEL_CONF:del all policy cite from ip_map success:ip="<<addr<<",policy="<<*policy_iter<<",count="<<result_iter->count; 
														ip_map[addr].ip_policy_result.erase(result_iter);
												}
												pthread_mutex_unlock(&ip_map[addr].mutex);
												break;
										}
								}
						}
				}

				for(url_iter = iter->second.url.begin() ; url_iter != iter->second.url.end() ; url_iter++)
				{
						if(servers[i].localURL == url_iter->localURL)
						{
								pthread_rwlock_wrlock(&dial_map_lock);
								iter->second.url.erase(url_iter);
								pthread_rwlock_unlock(&dial_map_lock);
								LOG(INFO)<<"DEL_CONF:del url_server from url_group success:url="<<servers[i].localURL<<",group="<<iter->first;
								break;
						}
				}
		}

		LOG(INFO)<<"DEL_CONF:del url_servers from url_group success:url_size="<<servers.size()<<",group="<<iter->first; 
		return RetCode::OK;
}

RetCode::type DialHandler:: addDialServer(const ObjectId& rid, const IpAddr& ip, const DialServerType::type typ)
{
		server_node_t server_node;
		server_node.srv_type = typ; 
		server_node.ip = ip; 

		pthread_rwlock_wrlock(&server_map_lock);
		server_map[rid] = server_node;
		pthread_rwlock_unlock(&server_map_lock);

		LOG(INFO)<<"ADD_CONF:add a server success:ip="<<ip.addr<<",id="<<rid<<",type="<<typ; 

		return RetCode::OK;
}

RetCode::type DialHandler:: delDialServer(const ObjectId& rid)
{
		map<string,server_node_t>::iterator iter = server_map.find(rid);

		if(iter == server_map.end())
		{
				LOG(INFO)<<"DEL_CONF:del a server failed not find:id="<<rid; 
				return RetCode::FAIL;
		}

		pthread_rwlock_wrlock(&server_map_lock);
		server_map.erase(iter);
		pthread_rwlock_unlock(&server_map_lock);

		LOG(INFO)<<"DEL_CONF:del a server success:id="<<rid; 

		return RetCode::OK;
}

RetCode::type DialHandler:: addDcInfo(const DcInfo& dc)
{
		ip_node_t ip_node;
		pthread_mutex_init(&ip_node.mutex,NULL);
		ip_policy_result_t ip_policy_result;
		ip_policy_result.dial_flag = false;
		ip_policy_result.count = 1;
		ip_policy_result.delay = 0;
		ip_policy_result.status = DialStatus::FAIL;

		int i = 0,size = dc.PolicyList.size();

		map<string,ip_node_t>::iterator ip_iter = ip_map.find(dc.ip.addr);	
		if(ip_iter == ip_map.end())
		{
				for(i = 0 ; i != size ; i++)
				{
						ip_policy_result.policyname = dc.PolicyList[i];
						ip_node.ip_policy_result.push_back(ip_policy_result);
				}
				pthread_rwlock_wrlock(&ip_map_lock);
				ip_map[dc.ip.addr] = ip_node;
				pthread_rwlock_unlock(&ip_map_lock);
				LOG(INFO)<<"ADD_CONF:add a new ip success:ip="<<dc.ip.addr<<",policy_num="<<dc.PolicyList.size();
		}
		else
		{
				vector<ip_policy_result_t>::iterator result_iter;

				for(i = 0 ; i != size ; i++)
				{
						for(result_iter = ip_map[dc.ip.addr].ip_policy_result.begin() ; result_iter != ip_map[dc.ip.addr].ip_policy_result.end() ; result_iter++)
						{
								if(dc.PolicyList[i] == result_iter->policyname)
								{
										pthread_mutex_lock(&ip_map[dc.ip.addr].mutex);
										result_iter->count++;
										pthread_mutex_unlock(&ip_map[dc.ip.addr].mutex);
										LOG(INFO)<<"ADD_CONF:add policy to ip success:ip="<<dc.ip.addr<<",policy="<<dc.PolicyList[i]<<",count="<<result_iter->count; 
										break;
								}
						}
						if(result_iter == ip_map[dc.ip.addr].ip_policy_result.end())
						{
								ip_policy_result.policyname = dc.PolicyList[i];
								pthread_mutex_lock(&ip_map[dc.ip.addr].mutex);
								ip_map[dc.ip.addr].ip_policy_result.push_back(ip_policy_result);
								pthread_mutex_unlock(&ip_map[dc.ip.addr].mutex);
								LOG(INFO)<<"ADD_CONF:add a new policy to ip success:ip="<<dc.ip.addr<<",policy="<<dc.PolicyList[i]<<",count="<<result_iter->count; 
						}
				}
		}

		dial_node_t dial_node;
		dial_node.type = DC; 
		dial_node.ip = dc.ip; 
		dial_node.policy = dc.PolicyList;

		pthread_rwlock_wrlock(&dial_map_lock);
		dial_map[dc.id] = dial_node;
		pthread_rwlock_unlock(&dial_map_lock);
		LOG(INFO)<<"ADD_CONF:add a new dc group success:group="<<dc.id<<",policy size="<<dc.PolicyList.size(); 
		return RetCode::OK;
}

RetCode::type DialHandler:: delDcInfo(const std::string& id)
{
		map<string,dial_node_t>::iterator iter = dial_map.find(id);

		if(iter == dial_map.end())
		{
				LOG(INFO)<<"DEL_CONF:del dc group failed:group="<<id; 
				return RetCode::FAIL;
		}
		
		vector<ip_policy_result_t>::iterator result_iter;
		int i = 0,size = iter->second.policy.size();

		for(i = 0 ; i != size ; i++)
		{
				for(result_iter = ip_map[iter->second.ip.addr].ip_policy_result.begin() ; result_iter != ip_map[iter->second.ip.addr].ip_policy_result.end() ; result_iter++)
				{
						if(iter->second.policy[i] == result_iter->policyname)
						{
								pthread_mutex_lock(&ip_map[iter->second.ip.addr].mutex);
								result_iter->count--;
								LOG(INFO)<<"DEL_CONF:del a policy from ip success:ip="<<iter->second.ip.addr<<",policy="<<iter->second.policy[i]<<",count="<<result_iter->count; 
								if(0 == result_iter->count)
								{
										LOG(INFO)<<"DEL_CONF:del all policy cite from ip success:ip="<<iter->second.ip.addr<<",policy="<<iter->second.policy[i]<<",count="<<result_iter->count; 
										ip_map[iter->second.ip.addr].ip_policy_result.erase(result_iter);
								}
								pthread_mutex_unlock(&ip_map[iter->second.ip.addr].mutex);
								break;
						}
				}
		}


		pthread_rwlock_wrlock(&dial_map_lock);
		dial_map.erase(iter);
		pthread_rwlock_unlock(&dial_map_lock);

		LOG(INFO)<<"DEL_CONF:del dc group success:group="<<id; 
		return RetCode::OK;
}


void DialHandler:: heartBeat(HeartBeatState& _return)
{
		if(register_status)
		{
				_return.__set_mState(ModuleState::REGISTERED);
		}	
		else
		{
				_return.__set_mState(ModuleState::STARTUP);
		}

		_return.__set_serverState(dial_status);

		LOG_EVERY_N(INFO,60)<<"heartBeat Server Status = "<<dial_status;
}

RetCode::type DialHandler:: setServerState(const bool enable)
{
		dial_status = enable;
		LOG(INFO)<<"dial_map_size="<<dial_map.size()<<",ip_map_size="<<ip_map.size()<<",server_map_size="<<server_map.size(); 
		LOG(INFO)<<"set Server Status = "<<enable; 

		return RetCode::OK;
}

RetCode::type DialHandler::addIpSec(const SysIpSec& ipsec,const int32_t interval)
{
		ipsec_node_t ipsec_node;
		ipsec_node.work_flag = true;
		ipsec_node.tid = 0;
		ipsec_node.ipsec = ipsec;
		ipsec_node.interval = interval;
		ipsec_map[ipsec.recordId] = ipsec_node;

		map<string,ipsec_node_t>::iterator iter = ipsec_map.find(ipsec.recordId);
		int res = pthread_create(&iter->second.tid,NULL,ipsec_work_thread,&iter->second);
		if(0 != res)
		{
				iter->second.tid = 0;
				iter->second.work_flag = false;
				LOG(ERROR)<<"create ipsec work thread failed,IP="<<iter->second.ipsec.ipsec.ip.addr;
				return RetCode::FAIL;
		}

		LOG(INFO)<<"ADD_CONF:add a ipsec node success!!,IPSEC="<<iter->second.ipsec.ipsec.ip.addr<<",TID="<<iter->second.tid;

		return RetCode::OK;
}


RetCode::type DialHandler::delIpSec(const std::string& ipsecid)
{
		int size = 0,res = 0;
		map<string,ipsec_node_t>::iterator iter;

		iter = ipsec_map.find(ipsecid);

		if(iter == ipsec_map.end())
		{
				return RetCode::FAIL;
		}
		
		if(iter->second.work_flag)
		{
				iter->second.work_flag = false;
				res = pthread_join(iter->second.tid,NULL);
				if(0 != res)
				{
						LOG(INFO)<<"DEL_CONF:del ipsec thread exit failed !!,IPSEC="<<ipsecid;
				}
		}

		const char* ip = iter->second.ipsec.ipsec.ip.addr.c_str();
		uint32_t net_addr = 0,host_addr = 0,broadcast_addr = 0;
		uint32_t i = 0,host_mask = 0,net_begin_addr = 0,tmp_addr = 0;
		char addr[32] = {'\0'};

		host_mask = cal_mask(32 - iter->second.ipsec.ipsec.mask);
		inet_pton(AF_INET,ip,&net_addr);
		host_addr = ntohl(net_addr);
		net_begin_addr = (host_addr & host_mask) + 1;
		broadcast_addr = (~host_mask)|host_addr;

		pthread_mutex_lock(&ping_set_lock);
		for(i = net_begin_addr ; i < broadcast_addr ; i++)
		{
				memset(addr,0,32);
				tmp_addr = htonl(i);
				inet_ntop(AF_INET,&tmp_addr,addr,32);
				if(ping_set.end() != ping_set.find(addr))
				{
						ping_set.erase(addr);
				}
		}
		pthread_mutex_unlock(&ping_set_lock);

		size = ipsec_map.erase(ipsecid);

		if(size > 0)
		{
				LOG(INFO)<<"DEL_CONF:del ipsec node success!!,IPSEC="<<ipsecid;
				return RetCode::OK;
		}		
		else
		{
				LOG(INFO)<<"DEL_CONF:del ipsec node failed!!,IPSEC="<<ipsecid;
				return RetCode::FAIL;
		}
}


RetCode::type DialHandler::addSnmpGroupInfo(const SnmpGroupInfo& snmp)
{
		snmp_node_t snmp_node;
		snmp_node.tid = 0;
		snmp_node.work_flag = true;
		snmp_node.snmp = snmp;
		snmp_map[snmp.name] = snmp_node;

		map<string,snmp_node_t>::iterator iter = snmp_map.find(snmp.name);
		int res = pthread_create(&iter->second.tid,NULL,snmp_work_thread,&iter->second);
		if(0 != res)
		{
				iter->second.tid = 0;
				iter->second.work_flag = false;
				LOG(ERROR)<<"create a snmp task thread failed!! IP="<<iter->second.snmp.ip.addr;
				return RetCode::FAIL;
		}
		LOG(INFO)<<"ADD_CONF:add a snmp node success!!,IP="<<iter->second.snmp.ip.addr<<",TID="<<iter->second.tid<<",ID="<<snmp.name;

		return RetCode::OK;
}


RetCode::type DialHandler::delSnmpGroupInfo(const std::string& snmp)
{
		int size = 0,res = 0;
		map<string,snmp_node_t>::iterator iter;
		
		iter = snmp_map.find(snmp);
		if(iter == snmp_map.end())
		{
				return RetCode::FAIL;
		}

		if(iter->second.work_flag)
		{
				res = pthread_cancel(iter->second.tid);
				if(0 != res)
				{
						LOG(INFO)<<"pthread_cancle thread failed id="<<snmp;
				}
		}		

		iter->second.process.clear();
		size = snmp_map.erase(snmp);

		if(size > 0)
		{
				LOG(INFO)<<"DEL_CONF:del a snmp node success!!,id="<<snmp;
				return RetCode::OK;
		}
		else
		{
				LOG(INFO)<<"DEL_CONF:del a snmp node failed!!,id="<<snmp;
				return RetCode::FAIL;
		}
}


RetCode::type DialHandler::addSnmpProcessInfo(const std::string& snmp, const std::string& processname)
{
		ProcessInfo process;	
		map<string,snmp_node_t>::iterator iter;
		
		iter = snmp_map.find(snmp);
		if(iter == snmp_map.end())
		{
				return RetCode::FAIL;
		}

		process.name = processname;
		snmp_map[snmp].process.push_back(process);
		
		LOG(INFO)<<"ADD_CONF:add proces success!!,process="<<processname<<",id="<<snmp;
		return RetCode::OK;
}


RetCode::type DialHandler::delSnmpProcessInfo(const std::string& snmp, const std::string& processname)
{
		map<string,snmp_node_t>::iterator iter;
		vector<ProcessInfo>::iterator piter;
		
		iter = snmp_map.find(snmp);
		if(iter == snmp_map.end())
		{
				return RetCode::FAIL;
		}

		for(piter = iter->second.process.begin() ; piter != iter->second.process.end() ; piter++)
		{
				if(piter->name == processname)
				{
						iter->second.process.erase(piter);
						LOG(INFO)<<"DEL_CONF:del proces success!!,process="<<processname<<",id="<<snmp;
						return RetCode::OK;
				}
		}

		LOG(INFO)<<"DEL_CONF:del proces failed!!,process="<<processname<<",id="<<snmp;
		return RetCode::FAIL;
}

void *reconnect_thread(void *arg)
{
		LOG(WARNING)<<"client_reconnect_thread: register start!";

		while(1) 
		{    
				sleep(1);

				try  
				{    
						transport_client->open(); 
				}    
				catch(std::exception &e)  
				{    
						LOG(WARNING)<<"client_reconnect_thread:catch an exception!-->"<<e.what();
						continue;
				}    
				register_status = true;
				break;
		}

		LOG(WARNING)<<"client_reconnect_thread: register success!!!";
		return NULL;
}

void reconnect_manager_server()
{
		LOG(WARNING)<<"connect erorr and reconnect manager server start!!!";

		register_status = false;

		if(transport_client->isOpen())
		{
				transport_client->close();
				LOG(WARNING)<<"close transport";
		}

		while(1) 
		{    
				sleep(2);

				try  
				{    
						transport_client->open(); 
				}    
				catch(std::exception &e)  
				{    
						LOG(WARNING)<<"reconnect_manager_server:catch an exception!-->"<<e.what();
						continue;
				}    
				register_status = true;
				break;
		}

		LOG(WARNING)<<"reconnect manager server success!!!";

		#if 0
		pthread_t reconnect_tid;
		register_status = false;
		transport_client->close();
		int rtn = pthread_create(&reconnect_tid,NULL,reconnect_thread,NULL);
		if(0 != rtn)
		{
				LOG(WARNING)<<"create register to manager thread failed!!!";
				exit_process();
		}
		#endif
}

void * register_to_manager(void*arg)
{
		RetCode::type ret = RetCode::FAIL;
		
		sleep(1);	// after thrift server start to register to manager

		while(true) 
		{
				try
				{
						transport_client->open(); 
						AgentClient client(protocol_client);
						ret = client.registerModule(ModuleType::DIALING);
						if(ret != RetCode::OK) 
						{
								LOG(INFO)<<"register to manager failed,continue!!!";
								sleep(1);
								continue;
						}
				}
				catch(std::exception &e) 
				{
						LOG(INFO)<<"register to manager:catch an exception!-->"<<e.what();
						sleep(1);
						continue;
				}
				register_status = true;
				break;
		}

		LOG(INFO)<<"register to manager success!!!";
		return NULL;
}

void thrift_server_init(int port)
{
		shared_ptr<DialHandler> handler(new DialHandler());
		shared_ptr<TProcessor> processor(new DialProcessor(handler));
		shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
		shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
		shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());

		TSimpleServer server(processor, serverTransport, transportFactory, protocolFactory);
		
		pthread_t register_tid;
		int rtn = pthread_create(&register_tid,NULL,register_to_manager,NULL);
		if(0 != rtn)
		{
				LOG(WARNING)<<"create register to manager thread failed!!!";
				exit_process();
		}

		LOG(INFO)<<"Thrift Dial Server Start!!!";
		server.serve();
}


void thrift_client_init(const char *ip,const int port)
{
		boost::shared_ptr<TSocket> tsocket(new TSocket(ip, port));  
		boost::shared_ptr<TTransport> ttransport(new TBufferedTransport(tsocket));  
		boost::shared_ptr<TProtocol> tprotocol(new TBinaryProtocol(ttransport)); 

		transport_client = ttransport;
		protocol_client = tprotocol;
}


int init_glock()
{
		if (0 != (pthread_rwlock_init(&dial_map_lock,NULL)))
		{
				return -1;
		}
		if (0 != (pthread_rwlock_init(&server_map_lock,NULL)))
		{
				return -1;
		}
		if (0 != (pthread_rwlock_init(&ip_map_lock,NULL)))
		{
				return -1;
		}
		if (0 != (pthread_mutex_init(&client_lock,NULL)))
		{
				return -1;
		}
		if (0 != (pthread_mutex_init(&common_queue_lock,NULL)))
		{
				return -1;
		}
		if (0 != (pthread_mutex_init(&udp_queue_lock,NULL)))
		{
				return -1;
		}
		if (0 != (pthread_mutex_init(&snmp_queue_lock,NULL)))
		{
				return -1;
		}
		if (0 != (pthread_mutex_init(&ping_set_lock,NULL)))
		{
				return -1;
		}
}


