#ifndef _WORK_H_
#define _WORK_H_

#include "server.h"
#include "epoll.h"

#define AUTH_RESULT_SIZE 20000
#define URL_RESULT_SIZE 1000
#define SERVER_RESULT_SIZE 500
#define DC_RESULT_SIZE 100

extern bool dial_status;
extern bool register_status;
extern pthread_mutex_t client_lock;

extern map<string,HealthPolicyInfo> policy_map;

extern map<string,dial_node_t> dial_map;
extern pthread_rwlock_t dial_map_lock;

extern map<string,server_node_t> server_map;
extern pthread_rwlock_t server_map_lock;

extern map<string,ip_node_t> ip_map;
extern pthread_rwlock_t ip_map_lock;

extern queue<ev_t*> common_queue;
extern pthread_mutex_t common_queue_lock;

extern queue<ev_t*> udp_queue;
extern pthread_mutex_t udp_queue_lock;

extern queue<ev_t*> snmp_queue;
extern pthread_mutex_t snmp_queue_lock;

extern set<string> ping_set;
extern pthread_mutex_t ping_set_lock;

extern boost::shared_ptr<TTransport> transport_client;  
extern boost::shared_ptr<TProtocol> protocol_client;

extern map<string,ipsec_node_t> ipsec_map;

void *ip_map_monitor(void*arg);
void *update_dial_result_thread(void*arg);

void process_init();
void init_thread();
void update_dial_status(enum dial_type type);

#endif
