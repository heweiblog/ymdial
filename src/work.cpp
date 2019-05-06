#include <string>
#include <sys/resource.h>
#include "log.h"
#include "work.h"
#include "tcp.h"
#include "icmp.h"
#include "http.h"
#include "epoll.h"
#include "dial_server.h"
#include "mysql.h"
#include "udp.h"
#include "snmp.h"


pthread_t g_ip_map_tid;
pthread_t g_epoll_common_tid;
pthread_t g_epoll_https_tid;
pthread_t g_result_tid;
pthread_t g_server_tid;
pthread_t g_icmp_recv_tid;
pthread_t g_icmp_check_tid;
pthread_t g_common_tid;
pthread_t g_udp_tid;
pthread_t g_snmp_tid;

vector<DialHealthResult> auth_results(AUTH_RESULT_SIZE);
vector<DialNginxResult> url_results(URL_RESULT_SIZE);
vector<DialServerResult> server_results(SERVER_RESULT_SIZE);
vector<DialDcResult> dc_results(DC_RESULT_SIZE);

void do_dial_by_policy(string & policy,const char* ip)
{
		switch(policy_map[policy].method)
		{
				case DIAL_TCPPORT:
				{
						handle_tcp_port_task(ip,policy_map[policy].port,policy.c_str(),DIAL_TCPPORT);
						break;
				}
				case DIAL_ICMP:
				{
						handle_icmp_task(ip);
						break;
				}
				case DIAL_HTTPGET:
				{
						handle_http_task(ip,policy.c_str(),DIAL_HTTPGET);
						break;
				}
				case DIAL_DATABASE:
				{
						handle_db_task(ip,policy.c_str(),DIAL_DATABASE);
						break;
				}
				case DIAL_EXTHTTPGET:
				{
						handle_http_task(ip,policy.c_str(),DIAL_EXTHTTPGET);
						break;
				}
				case DIAL_EXTHTTPPOST:
				{
						handle_http_task(ip,policy.c_str(),DIAL_EXTHTTPPOST);
						break;
				}
				case DIAL_HTTPCOMMON:
				{
						handle_http_task(ip,policy.c_str(),DIAL_HTTPCOMMON);
						break;
				}
				case DIAL_EXTTCPPORT:
				{
						handle_http_task(ip,policy.c_str(),DIAL_EXTTCPPORT);
						break;
				}
				case DIAL_UDPPORT:
				{
						handle_udp_port_task(ip,policy_map[policy].port,policy.c_str(),DIAL_UDPPORT);
						break;
				}
				case DIAL_FTP:
				{
						handle_ftp_task(ip,policy_map[policy].port,policy.c_str(),DIAL_FTP);
						break;
				}
				case DIAL_SMTP:
				{
						if(policy_map[policy].option.tag)
						{
								handle_http_task(ip,policy.c_str(),DIAL_SMTP);
						}
						else
						{
								handle_tcp_port_task(ip,policy_map[policy].port,policy.c_str(),DIAL_SMTP);
						}
						break;
				}
				case DIAL_SNMP:
				{
						handle_snmp_task(ip,policy_map[policy].port,policy.c_str(),DIAL_SNMP);
						break;
				}
				case DIAL_ORACLE:
				{
						handle_db_task(ip,policy.c_str(),DIAL_ORACLE);
						break;
				}
		}
}

void *ip_map_monitor(void*arg)
{
		map<string,ip_node_t>::iterator ip_iter;
		vector<ip_policy_result_t>::iterator result_iter;
		time_t t_start = time(NULL);
		time_t t_now = 0;

		while(true)
		{
				if(!dial_status || !register_status)
				{
						sleep(1);
						continue;
				}
				
				t_now = time(NULL);
				
				pthread_rwlock_rdlock(&ip_map_lock);

				for(ip_iter = ip_map.begin() ; ip_iter != ip_map.end() ; ip_iter++)
				{
						pthread_mutex_lock(&ip_iter->second.mutex);
						for(result_iter = ip_iter->second.ip_policy_result.begin() ; result_iter != ip_iter->second.ip_policy_result.end() ; result_iter++)
						{
								//LOG(INFO)<<"t_now="<<t_now<<"t_start="<<t_start<<"freq="<<policy_map[result_iter->policyname].freq<<"policy="<<result_iter->policyname;
								if(0 == ((t_now-t_start) % policy_map[result_iter->policyname].freq))
								{
										do_dial_by_policy(result_iter->policyname,ip_iter->first.c_str());
								}
						}
						pthread_mutex_unlock(&ip_iter->second.mutex);
				}

				pthread_rwlock_unlock(&ip_map_lock);
				sleep(1);
		}
}

void update_dial_status(enum dial_type type)
{
		RetCode::type rtn = RetCode::FAIL;

		pthread_mutex_lock(&client_lock);

		try
		{
				AgentClient client(protocol_client);
				
				switch(type)
				{
						case AUTH:
						{
								rtn = client.updateHealthStatus(auth_results);
								LOG(INFO)<<"report_auth_result:res="<<rtn<<",size="<<auth_results.size();
								break;
						}
						case URL:
						{
								rtn = client.updateNginxStatus(url_results);
								LOG(INFO)<<"report_url_result:res="<<rtn<<",size="<<url_results.size();
								break;
						}
						case DC:
						{
								rtn = client.updateDcStatus(dc_results);
								LOG(INFO)<<"report_dc_result:res="<<rtn<<",size="<<dc_results.size();
								break;
						}
						case SERVER:
						{
								rtn = client.updateServerStatus(server_results);
								LOG(INFO)<<"report_sever_result:res="<<rtn<<",size="<<server_results.size();
								break;
						}
				}
		}
		catch(std::exception &e) 
		{
				LOG(WARNING)<<"update dial result:catch an exception!--->"<<e.what();
				reconnect_manager_server();
		}

		pthread_mutex_unlock(&client_lock);
}

void *update_dial_result_thread(void*arg)
{
		auth_results.clear();
		url_results.clear();
		dc_results.clear();
		sleep(2);
		int interval = 0;
		uint32_t i = 0;
		time_t t_start = time(NULL);
		time_t t_now = 0;
		string addr;

		map<string,dial_node_t>::iterator iter;
		vector<string>::iterator policy_iter;
		vector<DialRecord>::iterator auth_iter;
		vector<DialNginxServer>::iterator url_iter;
		set<string>::iterator ping_iter;

		DialHealthResult auth_result;
		DialRecordStatus auth_status;

		DialNginxResult url_result;
		DialNginxStatus url_status;

		DialDcResult dc_result;

		while(true)
		{
				if(!dial_status || !register_status)
				{
						sleep(1);
						continue;
				}

				t_now = time(NULL);

				pthread_rwlock_rdlock(&dial_map_lock);
				for(iter = dial_map.begin() ; iter != dial_map.end() ; iter++)
				{
						for(policy_iter = iter->second.policy.begin() ; policy_iter != iter->second.policy.end() ; policy_iter++)
						{
								if(AUTH == iter->second.type)
								{
										auth_result.groupName = iter->first;
										auth_result.policyName = *policy_iter;

										for(auth_iter = iter->second.auth.begin() ; auth_iter != iter->second.auth.end() ; auth_iter++)
										{
												if(0 == ((t_now-t_start) % policy_map[*policy_iter].freq))
												{
														auth_status.rid = auth_iter->rid;

														pthread_mutex_lock(&ip_map[auth_iter->ip.addr].mutex);
														for(i = 0 ; i < ip_map[auth_iter->ip.addr].ip_policy_result.size() ; i++)
														{
																if(*policy_iter == ip_map[auth_iter->ip.addr].ip_policy_result[i].policyname)
																{
																		if(true == ip_map[auth_iter->ip.addr].ip_policy_result[i].dial_flag)
																		{
																				auth_status.delay = ip_map[auth_iter->ip.addr].ip_policy_result[i].delay;
																				auth_status.status = ip_map[auth_iter->ip.addr].ip_policy_result[i].status;
																				auth_result.statusList.push_back(auth_status);
																		}
																		else if(policy_map[*policy_iter].method == DialMethod::DIAL_IMCP)
																		{
																				ping_iter = ping_set.find(auth_iter->ip.addr);
																				if(ping_iter == ping_set.end())
																				{
																						auth_status.status = DialStatus::FAIL;
																				}
																				else
																				{
																						auth_status.status = DialStatus::OK;
																				}
																				auth_status.delay = 0;
																				auth_result.statusList.push_back(auth_status);
																		}
																		LOG(INFO)<<"auth_result:rid="<<auth_status.rid<<",ip="<<auth_iter->ip.addr<<",policy="<<*policy_iter<<",status="<<auth_status.status;
																}
														}
														pthread_mutex_unlock(&ip_map[auth_iter->ip.addr].mutex);
												}
										}
										if(auth_result.statusList.size() > 0)
										{
												auth_results.push_back(auth_result);
												auth_result.statusList.clear();
										}
								}
								else if(URL == iter->second.type)
								{
										url_result.groupName = iter->first;
										url_result.policyName = *policy_iter;

										for(url_iter = iter->second.url.begin() ; url_iter != iter->second.url.end() ; url_iter++)
										{
												if(0 == (t_now-t_start) % policy_map[*policy_iter].freq)
												{
														url_status.server.localURL = url_iter->localURL;
														addr = get_url_addr(url_status.server.localURL.c_str());

														pthread_mutex_lock(&ip_map[addr].mutex);
														for(i = 0 ; i < ip_map[addr].ip_policy_result.size() ; i++)
														{
																if(*policy_iter == ip_map[addr].ip_policy_result[i].policyname) 
																{
																		if(true == ip_map[addr].ip_policy_result[i].dial_flag)
																		{
																				url_status.delay = ip_map[addr].ip_policy_result[i].delay;
																				url_status.status = ip_map[addr].ip_policy_result[i].status;
																				url_result.statusList.push_back(url_status);
																		}
																		else if(policy_map[*policy_iter].method == DialMethod::DIAL_IMCP)
																		{
																				ping_iter = ping_set.find(addr);
																				if(ping_iter == ping_set.end())
																				{
																						url_status.status = DialStatus::FAIL;
																				}
																				else
																				{
																						url_status.status = DialStatus::OK;
																				}
																				url_status.delay = 0;
																				url_result.statusList.push_back(url_status);
																		}
																		LOG(INFO)<<"url_result:url="<<url_status.server.localURL<<",ip="<<addr<<",policy="<<*policy_iter<<",status="<<url_status.status;
																}
														}
														pthread_mutex_unlock(&ip_map[addr].mutex);
												}
										}
										if(url_result.statusList.size() > 0)
										{
												url_results.push_back(url_result);
												url_result.statusList.clear();
										}
								}
								else if(DC == iter->second.type)
								{
										dc_result.id = iter->first;
										dc_result.policy = *policy_iter;

										if(0 == (t_now-t_start) % policy_map[*policy_iter].freq)
										{
												pthread_mutex_lock(&ip_map[iter->second.ip.addr].mutex);
												for(i = 0 ; i < ip_map[iter->second.ip.addr].ip_policy_result.size() ; i++)
												{
														if(*policy_iter == ip_map[iter->second.ip.addr].ip_policy_result[i].policyname)
														{
																if(true == ip_map[iter->second.ip.addr].ip_policy_result[i].dial_flag)
																{
																		dc_result.delay = ip_map[iter->second.ip.addr].ip_policy_result[i].delay;
																		dc_result.status = ip_map[iter->second.ip.addr].ip_policy_result[i].status;
																		dc_results.push_back(dc_result);
																}
																else if(policy_map[*policy_iter].method == DialMethod::DIAL_IMCP)
																{
																		ping_iter = ping_set.find(iter->second.ip.addr);
																		if(ping_iter == ping_set.end())
																		{
																				dc_result.status = DialStatus::FAIL;
																		}
																		else
																		{
																				dc_result.status = DialStatus::OK;
																		}
																		dc_result.delay = 0;
																		dc_results.push_back(dc_result);
																		LOG(INFO)<<"dc_result:dc_id="<<dc_result.id<<",ip="<<iter->second.ip.addr<<",policy="<<*policy_iter<<",status="<<dc_result.status;
																}
														}
												}
												pthread_mutex_unlock(&ip_map[iter->second.ip.addr].mutex);
										}
								}
						}
				}

				pthread_rwlock_unlock(&dial_map_lock);

				if(auth_results.size() > 2000 || ((0 == ((t_now-t_start) % 5)) && auth_results.size() > 0))
				{
						update_dial_status(AUTH);
						auth_results.clear();
				}
				if(url_results.size() > 2000 || ((0 == ((t_now-t_start) % 5)) && url_results.size() > 0))
				{
						update_dial_status(URL);
						url_results.clear();
				}

				if(dc_results.size() > 2000 || ((0 == ((t_now-t_start) % 5)) && dc_results.size() > 0))
				{
						update_dial_status(DC);
						dc_results.clear();
				}

				sleep(1);
		}
}

void init_thread()
{
		if(0 != pthread_create(&g_ip_map_tid,NULL,ip_map_monitor,NULL))
		{
				LOG(WARNING)<<"create thread failed";
				exit_process();
		}
		if(0 != pthread_create(&g_epoll_common_tid,NULL,common_epoll_thread,NULL))
		{
				LOG(WARNING)<<"create common epoll thread failed";
				exit_process();
		}
		if(0 != pthread_create(&g_epoll_https_tid,NULL,https_epoll_thread,NULL))
		{
				LOG(WARNING)<<"create https epoll thread failed";
				exit_process();
		}
		if(0 != pthread_create(&g_result_tid,NULL,update_dial_result_thread,NULL))
		{
				LOG(WARNING)<<"create result thread failed";
				exit_process();
		}
		if(0 != pthread_create(&g_server_tid,NULL,server_dial_thread,NULL))
		{
				LOG(WARNING)<<"create server dial thread failed";
				exit_process();
		}
		if(0 != pthread_create(&g_icmp_recv_tid,NULL,icmp_recv_thread,NULL))
		{
				LOG(WARNING)<<"create icmp recv dial thread failed";
				exit_process();
		}
		if(0 != pthread_create(&g_icmp_check_tid,NULL,icmp_check_thread,NULL))
		{
				LOG(WARNING)<<"create icmp check dial thread failed";
				exit_process();
		}
		if(0 != pthread_create(&g_common_tid,NULL,mysql_dial_thread,NULL))
		{
				LOG(WARNING)<<"create mysql dial thread failed";
				exit_process();
		}
		if(0 != pthread_create(&g_udp_tid,NULL,udp_dial_thread,NULL))
		{
				LOG(WARNING)<<"create udp dial thread failed";
				exit_process();
		}
		if(0 != pthread_create(&g_snmp_tid,NULL,snmp_policy_thread,NULL))
		{
				LOG(WARNING)<<"create snmp policy thread failed";
				exit_process();
		}
}

int change_tcp_sys_timeout()
{
		FILE* fp = popen("sysctl -w net.ipv4.tcp_syn_retries=1","r");
		if(NULL == fp)
		{    
				return -1;
		}    
		pclose(fp);

		return 0;
}


int set_core_file()
{
		struct rlimit rlim_new,rlim;

		if (getrlimit(RLIMIT_CORE, &rlim)==0) 
		{
				rlim_new.rlim_cur = rlim_new.rlim_max = RLIM_INFINITY;
				if (setrlimit(RLIMIT_CORE, &rlim_new)!=0) 
				{
						rlim_new.rlim_cur = rlim_new.rlim_max = rlim.rlim_max;
						(void) setrlimit(RLIMIT_CORE, &rlim_new);     
						LOG(ERROR)<<"set_core_file:setrlimit failed!!";
						return -1;
				}    
		}
		else
		{
				LOG(ERROR)<<"set_core_file:getrlimit failed!!";
				return -1;
		}    

		return 0;
}


int set_file_limit()
{
		struct rlimit tmp = {262143,262144};
		int rtn = setrlimit(RLIMIT_NOFILE,&tmp); 
		if(rtn != 0)
		{
				return -1;
		}
		LOG(INFO)<<"set file max rlim_cur="<<tmp.rlim_cur<<",rlimt_max="<<tmp.rlim_max;
		return 0;
}


void process_init()
{
		if(change_tcp_sys_timeout() < 0)
		{
				LOG(WARNING)<<"change tcp connect timeout failed";
				exit_process();
		}		
		if(init_glock() < 0)
		{
				LOG(WARNING)<<"init g_lock failed!!!";
				exit_process();
		}
		if(init_epoll() < 0)
		{
				LOG(WARNING)<<"init epoll handle fd failed";
				exit_process();
		}
		if(init_icmp() < 0)
		{
				LOG(WARNING)<<"init icmp failed";
				exit_process();
		} 
		if(set_file_limit() < 0)
		{
				LOG(WARNING)<<"set file max limit failed";
				exit_process();
		}

		set_core_file();
		init_ssl();
}



