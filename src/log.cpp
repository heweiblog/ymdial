#include "log.h"

void init_log(bool debug,char**argv)
{
		google::InitGoogleLogging(argv[0]);
		if(debug)
		{
				FLAGS_logtostderr = true;  //设置日志消息是否转到标准输出而不是日志文件
				FLAGS_alsologtostderr = true;   //设置日志消息除了日志文件之外是否去标准输出
		}
		else
		{
				FLAGS_logtostderr = false;  //设置日志消息是否转到标准输出而不是日志文件
				FLAGS_alsologtostderr = false;   //设置日志消息除了日志文件之外是否去标准输出
		}
		FLAGS_logbufsecs = 0; 		//缓冲日志输出，默认为30秒，此处改为立即输出
		FLAGS_max_log_size = 5120; 	//最大日志大小为 5120MB
		FLAGS_stop_logging_if_full_disk = true; 	//当磁盘被写满时，停止日志输出
		FLAGS_log_prefix = true;  	//设置日志前缀是否应该添加到每行输出
		FLAGS_log_dir = "/var/log/ymdial/";    //预创建好
}

void log_destroy()
{
		google::ShutdownGoogleLogging();
}

