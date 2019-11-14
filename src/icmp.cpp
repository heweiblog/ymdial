#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

#include "log.h"
#include "common.h"
#include "work.h"
#include "icmp.h"

int g_icmp_send_fd = 0;
int g_icmpv6_send_fd = 0;
unsigned char *aucSendBuf = NULL;
int iPktLen = 0;
uint16_t g_pid = 0;
pthread_rwlock_t ipsec_clear_lock;


int create_raw_fd(bool is_ipv6)
{
		int fd = 0;
		if(is_ipv6)
		{
			fd = socket(AF_INET6, SOCK_RAW,IPPROTO_ICMPV6);
		}
		else
		{
			fd = socket(AF_INET, SOCK_RAW,IPPROTO_ICMP);
		}

		if(fd <= 0)
		{
				return -1;
		}

		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 10*1000;

		int rtn = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval));
		if(rtn < 0)
		{       
				close(fd);
				return -1;
		}
		
		return fd;
}


int init_icmp()
{
		pthread_rwlock_init(&ipsec_clear_lock,NULL);
		g_pid = getpid();

		g_icmp_send_fd = create_raw_fd(false);
		if(g_icmp_send_fd < 0)
		{
				return -1;
		}

		g_icmpv6_send_fd = create_raw_fd(true);
		if(g_icmpv6_send_fd < 0)
		{
				return -1;
		}


		aucSendBuf = (unsigned char *)calloc(1,ICMP_BUFF_LEN);
		if(!aucSendBuf)
		{
				return -1;
		}

		iPktLen = new_icmp_echo(1,aucSendBuf,ICMP_DATA_LEN);

		LOG(INFO)<<"g_icmp_send_fd = "<<g_icmp_send_fd<<",iPktLen = "<<iPktLen<<"pid = "<<g_pid;

		return 0;
}


unsigned short calc_icmp_chksum(const void *pPacket, int iPktLen)
{   
		unsigned short usChkSum = 0;
		unsigned short *pusOffset = NULL;
		pusOffset = (unsigned short *)pPacket;

		while(1 < iPktLen)
		{   
				usChkSum += *pusOffset++;
				iPktLen -= sizeof(unsigned short);
		}

		if (1 == iPktLen)
		{   
				usChkSum += *((char *)pusOffset);
		}

		usChkSum = (usChkSum >> 16) + (usChkSum & 0xffff);
		usChkSum += (usChkSum >>16);

		return ~usChkSum;
}

int new_icmp_echo(const int iPacketNum, unsigned char *aucSendBuf,const int iDataLen)
{
		struct icmp *pstIcmp = NULL;
		pstIcmp = (struct icmp *)aucSendBuf;
		pstIcmp->icmp_type = ICMP_ECHO;
		pstIcmp->icmp_code = 0;
		pstIcmp->icmp_seq = htons((unsigned short)iPacketNum);
		pstIcmp->icmp_id = htons((unsigned short)g_pid);
		pstIcmp->icmp_cksum = 0;
		pstIcmp->icmp_cksum = calc_icmp_chksum(pstIcmp, iDataLen + 8);
		return iDataLen + 8;
}


int handle_icmp_task(const char* ip)
{
		if(ping_set.find(ip) != ping_set.end())
		{
				return 1;
		}
	
		if(strstr(ip,"::"))
		{
				struct sockaddr_in6 pstDestAddr;
				memset(&pstDestAddr, 0, sizeof(pstDestAddr));
				pstDestAddr.sin6_family = AF_INET6;
				inet_pton(AF_INET6,ip,&pstDestAddr.sin6_addr);
		
				return sendto(g_icmpv6_send_fd,aucSendBuf,iPktLen,0,(struct sockaddr*)&pstDestAddr,sizeof(struct sockaddr_in6));
		}
		else
		{
				struct sockaddr_in pstDestAddr;
				memset(&pstDestAddr, 0, sizeof(pstDestAddr));
				pstDestAddr.sin_family = AF_INET;
				inet_pton(AF_INET,ip,&pstDestAddr.sin_addr);

				return sendto(g_icmp_send_fd,aucSendBuf,iPktLen,0,(struct sockaddr*)&pstDestAddr,sizeof(struct sockaddr_in));
		}
}


void *icmp_recv_thread(void*arg)
{
		int fd = create_raw_fd(false);
		if(fd < 0)
		{
				LOG(WARNING)<<"create ipv4 raw socket error";
				exit_process();
		}
		LOG(INFO)<<"icmp_recv_fd="<<fd;

		int iRecvLen = 0,i = 0;
		char addr[20] = {'\0'};
		socklen_t fromLen = sizeof(struct sockaddr_in);
		struct sockaddr_in stFromAddr;
		unsigned char *aucRecvBuf = (unsigned char *)malloc(ICMP_BUFF_LEN);

		while(true)
		{
				iRecvLen = recvfrom(fd, (void *)aucRecvBuf,ICMP_BUFF_LEN, 0, (struct sockaddr *)&stFromAddr,&fromLen);
				if(iRecvLen <= 0)
				{
						continue;
				}
				inet_ntop(AF_INET,&stFromAddr.sin_addr,addr,20);

				pthread_mutex_lock(&ping_set_lock);
				ping_set.insert(addr);
				pthread_mutex_unlock(&ping_set_lock);
		}
}


void *icmpv6_recv_thread(void*arg)
{
		int fd = create_raw_fd(true);
		if(fd < 0)
		{
				LOG(WARNING)<<"create ipv6 raw socket error";
				exit_process();
		}
		LOG(INFO)<<"icmpv6_recv_fd="<<fd;

		int iRecvLen = 0,i = 0;
		char addr[64] = {'\0'};
		socklen_t fromLen = sizeof(struct sockaddr_in6);
		struct sockaddr_in6 stFromAddr;
		unsigned char *aucRecvBuf = (unsigned char *)malloc(ICMP_BUFF_LEN);

		while(true)
		{
				iRecvLen = recvfrom(fd, (void *)aucRecvBuf,ICMP_BUFF_LEN, 0, (struct sockaddr *)&stFromAddr,&fromLen);
				if(iRecvLen <= 0)
				{
						continue;
				}
				inet_ntop(AF_INET6,&stFromAddr.sin6_addr,addr,64);

				pthread_mutex_lock(&ping_set_lock);
				ping_set.insert(addr);
				pthread_mutex_unlock(&ping_set_lock);
		}
}


void *icmp_check_thread(void*arg)
{
		map<string,ip_node_t>::iterator iter;

		while(true)
		{
				pthread_rwlock_wrlock(&ipsec_clear_lock);
				pthread_mutex_lock(&ping_set_lock);
				ping_set.clear();
				pthread_mutex_unlock(&ping_set_lock);
				pthread_rwlock_unlock(&ipsec_clear_lock);

				for(iter = ip_map.begin() ; iter != ip_map.end() ; iter++)
				{
						if(iter->second.ip_policy_result.size() > 0)
						{
								while(handle_icmp_task((iter->first).c_str()) < 0)
								{
										usleep(10000);
								}
						}
				}

				sleep(7);
		}
}

uint32_t cal_mask(int val)
{
		int i = 0;
		uint32_t res = 1;
		for(i = 0 ; i < val ; i++)
		{
				res *= 2;		
		}
		res -= 1;
		return ~res;
}


RetCode::type update_ipsec_online_ip(const std::string& ipsecid, const std::vector<IpAddr> & iplist)
{
		RetCode::type rtn = RetCode::OK;

		pthread_mutex_lock(&client_lock);

		try
		{
				AgentClient client(protocol_client);
				rtn = client.updateIpSecOnlineIp(ipsecid,iplist);
				LOG(INFO)<<"update_ipsec_online_ip:ipsecid="<<ipsecid<<",iplist_szie="<<iplist.size()<<",rtn="<<rtn;
		}
		catch(std::exception &e) 
		{
				reconnect_manager_server();
		}

		pthread_mutex_unlock(&client_lock);

		return rtn;
}

void* ipsec_work_thread(void * arg)
{
		extern map<string,ipsec_node_t> ipsec_map;
		ipsec_node_t* ipsec = (ipsec_node_t*)arg;
		const char* ip = ipsec->ipsec.ipsec.ip.addr.c_str();
		uint32_t net_addr = 0,host_addr = 0,broadcast_addr = 0;
		uint32_t i = 0,host_mask = 0,net_begin_addr = 0,tmp_addr = 0;
		int rtn = 0,fd = 0,times = 0,j = 0;
		char addr[32] = {'\0'};

		host_mask = cal_mask(32 - ipsec->ipsec.ipsec.mask);
		inet_pton(AF_INET,ip,&net_addr);
		host_addr = ntohl(net_addr);
		net_begin_addr = (host_addr & host_mask) + 1;
		broadcast_addr = (~host_mask)|host_addr;

		vector<IpAddr> iplist;
		IpAddr tmp_ip;
		tmp_ip.version = 4;

		while(ipsec->work_flag)
		{
				pthread_rwlock_rdlock(&ipsec_clear_lock);
				for(times = 0 ; times < 3 ; times++)
				{
						for(i = net_begin_addr ; i < broadcast_addr ; i++)
						{
								if(false == ipsec->work_flag)
								{
										iplist.clear();
										close(fd);
										return NULL;
								}
								tmp_addr = htonl(i);
								inet_ntop(AF_INET,&tmp_addr,addr,32);
								while(handle_icmp_task(addr) < 0)
								{
										usleep(10000);
								}
						}
				}

				sleep(2);

				pthread_mutex_lock(&ping_set_lock);
				for(i = net_begin_addr ; i < broadcast_addr ; i++)
				{
						tmp_addr = htonl(i);
						inet_ntop(AF_INET,&tmp_addr,addr,32);
						tmp_ip.addr.assign(addr);
						if(ping_set.find(tmp_ip.addr) != ping_set.end())
						{
								iplist.push_back(tmp_ip);
						}
				}
				pthread_mutex_unlock(&ping_set_lock);
				pthread_rwlock_unlock(&ipsec_clear_lock);

				update_ipsec_online_ip(ipsec->ipsec.recordId,iplist);
				iplist.clear();

				if(0 == ipsec->interval)
				{
						ipsec_map.erase(ipsec->ipsec.recordId);
						ipsec->work_flag = false;
						close(fd);
						return NULL;
				}

				for(j = 0 ; j < ipsec->interval ; j++)
				{
						if(false == ipsec->work_flag)
						{
								close(fd);
								return NULL;
						}
						sleep(1);
				}

		}

		ipsec->work_flag = false;
		close(fd);
		return NULL;
}

/*

set<string>local_ip_set;

int get_local_ip()
{
		char *ip = NULL;
        int fd, intrface, retn = 0;
        struct ifreq buf[INET_ADDRSTRLEN];
        struct ifconf ifc;

        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
        {
                ifc.ifc_len = sizeof(buf);
                // caddr_t,linux内核源码里定义的：typedef void *caddr_t；
                ifc.ifc_buf = (caddr_t)buf;
                if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
                {
                        intrface = ifc.ifc_len/sizeof(struct ifreq);
                        while (intrface-- > 0)
                        {
                                if (!(ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface])))
                                {
                                        ip=(inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr));
										if(ip != NULL)
										{
                                        		local_ip_set.insert(ip);
												LOG(INFO)<<"local_ip = "<<ip;
										}
                                }
                        }
                }
        		close(fd);
        		return 0;
        }
		return -1;
}

void *icmp_check_thread(void*arg)
{
		set<string> tmp_set;
		set<string>::iterator iter;

		while(true)
		{
				pthread_mutex_lock(&ping_set_lock);
				tmp_set = ping_set;
				ping_set.clear();
				pthread_mutex_unlock(&ping_set_lock);

				for(iter = tmp_set.begin() ; iter != tmp_set.end() ; iter++)
				{
						handle_icmp_task((*iter).c_str());
						usleep(1000);
				}

				tmp_set.clear();

				sleep(7);
		}
}

int new_raw_block_socket()
{
		int fd = socket(AF_INET, SOCK_RAW,IPPROTO_ICMP);
		if(fd < 0)
		{
				return -1;
		}

		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 10*1000;

		int rtn = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval));
		if(rtn < 0)
		{       
				close(fd);
				return -1;
		}

		timeout.tv_sec = 0;
		timeout.tv_usec = 500*1000;
		rtn = setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));
		if(rtn < 0)
		{   
				close(fd);
				return -1;
		} 
		
		return fd;
}


int parseIcmp(unsigned char *pRecvBuf, const int iLen)
{
		int iIpHeadLen = 0;
		int iIcmpLen = 0;
		struct ip *pstIp = NULL;
		struct icmp *pstIcmpReply = NULL;
		pstIp = (struct ip *)pRecvBuf;
		iIpHeadLen = pstIp->ip_hl << 2;

		pstIcmpReply = (struct icmp *)(pRecvBuf + iIpHeadLen);

		iIcmpLen = iLen - iIpHeadLen;

		if(iIcmpLen < 8)
		{
				return -1;
		}

		if(pstIcmpReply->icmp_type == ICMP_ECHO)
		{
				return 1;
		}

		if(pstIcmpReply->icmp_type == ICMP_ECHOREPLY)
		{
				if(pstIcmpReply->icmp_id == g_pid)
				{
						return 0;
				}
				return 1;
		}

		return -1;
}

void *icmp_check_thread(void*arg)
{
		int recv_len = 0,res = 0,count = 0;
		char addr[32] = {'\0'};
		struct timeval t_start;
		struct timeval t_end;
		set<string>::iterator iter;
		struct sockaddr_in pstDestAddr;
		memset(&pstDestAddr, 0, sizeof(pstDestAddr));
		pstDestAddr.sin_family = AF_INET;
		socklen_t fromLen = sizeof(struct sockaddr_in);
		struct sockaddr_in stFromAddr;

		unsigned char *aucRecvBuf = (unsigned char *)malloc(ICMP_BUFF_LEN);
		if(!aucRecvBuf)
		{
				LOG(WARNING)<<"malloc failed";
				exit_process();
		}
		
		int fd = new_raw_block_socket();
		if(fd < 0)
		{
				LOG(WARNING)<<"create raw block fd failed";
				exit_process();
		}
		
		LOG(INFO)<<"icmp_check_fd="<<fd;

		while(true)
		{
				iter = ping_set.begin(); 
				while(iter != ping_set.end())
				{
						inet_pton(AF_INET,(*iter).c_str(),&pstDestAddr.sin_addr.s_addr);
						if(sendto(fd,aucSendBuf,iPktLen,0,(struct sockaddr*)&pstDestAddr,sizeof(struct sockaddr_in)) < 0)
						{
								break;
						}
						
						count = 0;
						while(true)
						{
								memset(aucRecvBuf,0,ICMP_BUFF_LEN);
								if((recv_len = recvfrom(fd, (void *)aucRecvBuf,ICMP_BUFF_LEN, 0, (struct sockaddr *)&stFromAddr,&fromLen)) > 0)
								{
										if(pstDestAddr.sin_addr.s_addr != stFromAddr.sin_addr.s_addr)
										{
												if(count >= 5)
												{
														pthread_mutex_lock(&ping_set_lock);
														ping_set.erase(iter++);
														pthread_mutex_unlock(&ping_set_lock);
														break;
												}
												count++;
												continue;
										}

										res = parseIcmp(aucRecvBuf,recv_len);
										if(0 == res)
										{
												iter++;
												break;
										}
										else if(1 == res)
										{
												if(count >= 5)
												{
														pthread_mutex_lock(&ping_set_lock);
														ping_set.erase(iter++);
														pthread_mutex_unlock(&ping_set_lock);
														break;
												}
												count++;
												continue;
										}
										else if(res < 0)
										{
												//LOG(WARNING)<<"ping failed,parse failed ip="<<*iter;
												pthread_mutex_lock(&ping_set_lock);
												ping_set.erase(iter++);
												pthread_mutex_unlock(&ping_set_lock);
										}
								}
								else
								{
										//LOG(WARNING)<<"ping failed,recv timeout ip="<<*iter;
										pthread_mutex_lock(&ping_set_lock);
										ping_set.erase(iter++);
										pthread_mutex_unlock(&ping_set_lock);
								}
						}
				}

				sleep(7);
		}
}
*/


