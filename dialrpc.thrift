namespace c_glib dialrpc
namespace java rpc.dial.yamutech.com
namespace cpp rpc.dial.yamutech.com
namespace * rpc.dial.yamutech.com

exception Xception 
{
  1: i32 errorCode,
  2: string message
}

typedef string ObjectId 

enum ModuleType
{
  DIALING = 2
}

enum DialStatus
{
  OK = 0,
  FAIL
}

enum RetCode
{
  OK = 0, 
  FAIL 
}

enum DialMethod
{
  DIAL_TCPPORT = 0, 
  DIAL_IMCP,
  DIAL_HTTPGET,
  DIAL_DATABASE,
  DIAL_EXTHTTPGET,
  DIAL_EXTTCPPORT,
  DIAL_EXTHTTPPOST,
  DIAL_HTTPCOMMON,
  DIAL_UDPPORT, 
  DIAL_FTP,
  DIAL_SMTP,
  DIAL_SNMP,
  DIAL_ORACLE
}

enum ModuleState
{
  STARTUP=0,
  REGISTERED
}

enum SysCommand
{
  RestoreConfig = 0
}

enum DialServerType
{
  XPROXY=0,
  REDIRECT,
  XFORWARD,
  DATACENTER
}

struct HeartBeatState
{
  1:ModuleState mState,
  2:bool serverState,
}

struct IpAddr
{
  1: i32 version,
  2: string addr  
}

struct IpsecAddress
{
  1: IpAddr ip,
  2: i32 mask
}

struct SysIpSec
{
  1: string name, 
  2: IpsecAddress ipsec,
  3: string recordId
}

struct DialOption
{
  1: string destUrl,
  2: string testMethod,
  3: list<i32> expectCode,
  4: string expectMatch,
  5: string contentType,
  6: i32 tag
}

struct HealthPolicyInfo
{
  1: string name,
  2: DialMethod method,
  3: optional i16 port,
  4: i32 freq,
  5: i32 times,
  6: i32 passed,
  7: DialOption option
}

struct DialRecord
{
  1: ObjectId rid,
  2: IpAddr ip,
  3: i32 ttl,
  4: i32 priority,
  5: bool enabled
}

struct DialRecordStatus 
{
  1: ObjectId rid,
  2: DialStatus status,
  3: i64 delay
}

struct DialHealthResult
{
  1: string groupName,
  2: string policyName,
  3: list<DialRecordStatus> statusList,
}

struct DialNginxServer
{
  1: string localURL,
  2: i32 priority
}

struct DialNginxStatus
{
  1: DialNginxServer server,
  2: DialStatus status,
  3: i64 delay
}

struct DialNginxResult
{
  1: string groupName,
  2: string policyName,
  3: list<DialNginxStatus> statusList,
}

struct DialServerStatus
{
  1: ObjectId rid,
  2: IpAddr ip,
  3: DialStatus status,
  4: i64 delay
}

struct DialServerResult
{
  1: DialServerStatus status,
  2: DialServerType typ
}

struct DcInfo
{
  1: string id,
  2: IpAddr ip,
  3: list<string> PolicyList
}

struct DialDcResult
{
  1: string id,
  2: string policy,
  3: DialStatus status,
  4: i64 delay
}

enum SnmpDevType
{
  HOST=0,
  ROUTER,
  H3C,
  HUAWEI,
  CISCO
}

struct SnmpGroupInfo
{
  1: bool enable,
  2: string name,
  3: string community,
  4: string user,
  5: string passwd,
  6: i32 version,
  7: i32 interval,
  8: i32 port,
  9: IpAddr ip,
  10: SnmpDevType type
}

struct InterfaceTraffic
{
  1: i32 index,
  2: i64 inoctets,
  3: i64 outoctets
}

struct IpMac
{
  1: i32 index,
  2: IpAddr ip,
  3: string physaddress
}

struct MacTable
{
  1: string macaddress,
  2: i32 index,
  3: string portname
}

struct InterfaceInfo
{
  1: i32 index,
  2: string descr,
  3: i32 type,
  4: i32 status,
  5: i64 speed,
  6: i32 mtu,
  7: string physaddress
}

struct RouteInfo
{
  1: i32 ifindex,
  2: IpAddr destination,
  3: IpAddr gateway,
  4: IpAddr genmask,
  5: i32 type,
  6: i32 proto
}

struct SysInfo
{
  1: i32 load,
  2: i32 usercpu, 
  3: i32 syscpu, 
  4: i32 idlecpu, 
  5: i32 totalmem, 
  6: i32 freemem, 
  7: i32 buffer, 
  8: i32 cache, 
  9: i32 availmem 
}

struct ProcessInfo
{
  1: string name,
  2: bool existflag, 
  3: i32 pid,
  4: i32 cputime, 
  5: i32 usedmem
}

service Agent
{
  RetCode         registerModule(1: ModuleType typ) throws(1: Xception ex),
  RetCode         updateHealthStatus(1: list<DialHealthResult> results) throws(1: Xception ex),
  RetCode         updateServerStatus(1: list<DialServerResult> results) throws(1: Xception ex),
  RetCode         updateDcStatus(1: list<DialDcResult> results) throws(1: Xception ex),
  RetCode         updateNginxStatus(1: list<DialNginxResult> results) throws(1: Xception ex),
  RetCode         updateSysInfo(1: string snmp,2: SysInfo sysinfo) throws(1: Xception ex),
  RetCode         updateInterfaceInfo(1: string snmp,2: list<InterfaceInfo> interfaces) throws(1: Xception ex),
  RetCode         updateInterfaceTraffic(1: string snmp,2: list<InterfaceTraffic> traffic) throws(1: Xception ex),
  RetCode         updateInterfaceIpMac(1: string snmp,2: list<IpMac> ipmac) throws(1: Xception ex),
  RetCode         updateRouteInfo(1: string snmp,2: list<RouteInfo> routeinfo) throws(1: Xception ex),
  RetCode         updateProcessInfo(1: string snmp,2: ProcessInfo processinfo) throws(1: Xception ex),
  RetCode         updateIpSecOnlineIp(1: string ipsecid,2: list<IpAddr> iplist) throws(1: Xception ex),
  RetCode         updateMacTable(1: string snmp,2: list<MacTable> mactable) throws(1: Xception ex)
}


service Dial
{
  RetCode         systemCommand(1: SysCommand cmdType) throws(1: Xception ex),
  RetCode         addHealthGroup(1: string groupName,2: string policyName) throws(1: Xception ex),
  RetCode         delHealthGroup(1: string groupName,2: string policyName) throws(1: Xception ex),
  RetCode         addHealthRecord(1: string groupName,2:list<DialRecord> records) throws(1: Xception ex),
  RetCode         delHealthRecord(1: string groupName,2:list<DialRecord> records) throws(1: Xception ex),
  RetCode         addHealthPolicy(1: HealthPolicyInfo policy) throws(1: Xception ex),
  RetCode         modHealthPolicy(1: HealthPolicyInfo policy) throws(1: Xception ex),
  RetCode         delHealthPolicy(1: HealthPolicyInfo policy) throws(1: Xception ex),
  RetCode         addDialServer(1:ObjectId rid, 2: IpAddr ip,3: DialServerType typ) throws(1: Xception ex),
  RetCode         delDialServer(1:ObjectId rid) throws(1: Xception ex),
  RetCode         addNginxGroup(1: string groupName,2: string policyName) throws(1:Xception ex),
  RetCode         delNginxGroup(1: string groupName,2: string policyName) throws(1:Xception ex),
  RetCode         addNginxServer(1: string groupName,2: list<DialNginxServer> servers) throws(1:Xception ex),
  RetCode         delNginxServer(1: string groupName,2: list<DialNginxServer> servers) throws(1:Xception ex),
  HeartBeatState  heartBeat() throws(1: Xception ex),
  RetCode   	  setServerState(1:bool enable) throws(1: Xception ex)
  RetCode         addSnmpGroupInfo(1: SnmpGroupInfo snmp) throws(1: Xception ex),
  RetCode         delSnmpGroupInfo(1: string snmp) throws(1: Xception ex)
  RetCode         addSnmpProcessInfo(1: string snmp,2: string processname) throws(1: Xception ex),
  RetCode         delSnmpProcessInfo(1: string snmp,2: string processname) throws(1: Xception ex),
  RetCode         addIpSec(1: SysIpSec ipsec,2: i32 interval) throws(1: Xception ex),
  RetCode         delIpSec(1: string ipsecid) throws(1: Xception ex),
  RetCode         addDcInfo(1: DcInfo dc) throws(1: Xception ex),
  RetCode         delDcInfo(1: string id) throws(1: Xception ex)
}
