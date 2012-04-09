#ifndef MY_PPPOE_INCLUDE_H 
#define MY_PPPOE_INCLUDE_H 
#include "pcap.h" 
#include <windows.h>
#include <conio.h> 
#include <packet32.h> 
/*
#include <ntddndis.h> 
#include <string.h>
#include <process.h>
#include <winbase.h>
#include  <time.h>
#include <tchar.h>
*/
unsigned char* BuildPppoePacket(unsigned long srcIp, unsigned long destIp,unsigned short dstPort);
bool judge_pppoe(pcap_t *p,int cnt,pcap_handler callback);//判断pppoe函数
/* 回调函数原型 */
void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);
void PppoePacket();
bool flag=false;
unsigned short ProtocolType;
unsigned char verAndtype;
unsigned char Code;
unsigned short Session_id;
unsigned short Length; 
unsigned char srcmac[6];
unsigned char dstmac[6];
unsigned char pppoemac[6];

unsigned long srcIP;
unsigned long dstIP;

//unsigned char srcIp[4];
//unsigned char dstIp[4];

//pppoe帧格式
typedef struct _PPPOE{
	unsigned char VerAndType;
	unsigned char Code;
	unsigned short Session_id;
	unsigned short Length;
}PPPOE;
#endif