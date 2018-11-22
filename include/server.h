#ifndef _SERVER_H_
#define _SERVER_H_

#include <vector>
#include <map>
#include <set>
#include <queue>
#include <string>

#include "common.h"
#include "Dial.h"
#include "Agent.h"
#include "thrift/protocol/TBinaryProtocol.h"
#include "thrift/protocol/TProtocol.h"
#include "thrift/server/TSimpleServer.h"
#include "thrift/transport/TServerSocket.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/transport/TSocket.h"

using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;

using boost::shared_ptr;

using namespace ::rpc::dial::yamutech::com;
using namespace std;


typedef struct server_node
{
		DialServerType::type srv_type;
		vector<string> policy;
		IpAddr ip;

}server_node_t;


typedef struct dial_node
{
		enum dial_type type;
		vector<string> policy;
		vector<DialRecord> auth;
		vector<DialNginxServer> url;
		IpAddr ip;

}dial_node_t;

typedef struct ip_policy_result
{
		bool dial_flag;
		string policyname;
		DialStatus::type status;
		int delay;
		int count;

}ip_policy_result_t;

typedef struct ip_node
{
		pthread_mutex_t mutex;
		vector<ip_policy_result_t> ip_policy_result;

}ip_node_t;

typedef struct snmp_node
{
		bool work_flag;
		pthread_t tid;
		SnmpGroupInfo snmp;
		vector<ProcessInfo> process; 
	
}snmp_node_t;


typedef struct ipsec_node
{
		bool work_flag;
		pthread_t tid;
		int interval;
		SysIpSec ipsec;

}ipsec_node_t;


class DialHandler : virtual public DialIf 
{
		public:
				RetCode::type systemCommand(const SysCommand::type cmdType);
				RetCode::type addHealthGroup(const std::string& groupName, const std::string& policyName);
				RetCode::type delHealthGroup(const std::string& groupName, const std::string& policyName);
				RetCode::type addHealthRecord(const std::string& groupName, const std::vector<DialRecord> & records);
				RetCode::type delHealthRecord(const std::string& groupName, const std::vector<DialRecord> & records);
				RetCode::type addHealthPolicy(const HealthPolicyInfo& policy);
				RetCode::type modHealthPolicy(const HealthPolicyInfo& policy);
				RetCode::type delHealthPolicy(const HealthPolicyInfo& policy);
				RetCode::type addDialServer(const ObjectId& rid, const IpAddr& ip, const DialServerType::type typ);
				RetCode::type delDialServer(const ObjectId& rid);
				RetCode::type addNginxGroup(const std::string& groupName, const std::string& policyName);
				RetCode::type delNginxGroup(const std::string& groupName, const std::string& policyName);
				RetCode::type addNginxServer(const std::string& groupName, const std::vector<DialNginxServer> & servers);
				RetCode::type delNginxServer(const std::string& groupName, const std::vector<DialNginxServer> & servers);
				void heartBeat(HeartBeatState& _return);
				RetCode::type setServerState(const bool enable);
				RetCode::type addSnmpGroupInfo(const SnmpGroupInfo& snmp);
				RetCode::type delSnmpGroupInfo(const std::string& snmp);
				RetCode::type addSnmpProcessInfo(const std::string& snmp, const std::string& processname);
				RetCode::type delSnmpProcessInfo(const std::string& snmp, const std::string& processname);
				RetCode::type addIpSec(const SysIpSec& ipsec,const int32_t interval);
				RetCode::type delIpSec(const std::string& ipsecid);
				RetCode::type addDcInfo(const DcInfo& dc);
				RetCode::type delDcInfo(const std::string& id);
};

string get_url_addr(const char* url);
int init_glock();
void thrift_server_init(const int port);
void thrift_client_init(const char *ip,const int port);
void register_to_manager();
void reconnect_manager_server();


#endif
