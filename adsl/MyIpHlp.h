#ifndef __MYIPHLP_H
#define __MYIPHLP_H

#define  MAC_MAX_LENTH  6
#include "Iphlpapi.h"


#define ETHER_ADDR_LEN 6  
#define ETHERTYPE_IP  0x0800


//获取网卡地址
BOOL GetMacByArp(DWORD dwIP,unsigned char *pMAC,ULONG ulLen)
{	
	ULONG   pulMac[2];   
	if(pMAC==NULL || ulLen>MAC_MAX_LENTH) return FALSE;
	memset(pulMac,0xff,sizeof(pulMac));   
	if(!SendARP (dwIP,0,pulMac,&ulLen))
	{
		memcpy(pMAC,(unsigned char*)pulMac,ulLen);
		return TRUE;
	}
	return FALSE;
}

//选择本地网卡，输出其name,mac,ip,netmask,gate,mac
BOOL GetLocalAdapter(char *pDevName,unsigned char* pMac,
					 DWORD &dwIP,DWORD &dwNetmask,DWORD &dwGateway)
{
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	ULONG ulLen = 0;

	::GetAdaptersInfo(pAdapterInfo,&ulLen);
	pAdapterInfo = (PIP_ADAPTER_INFO)new char[ulLen];	
	if(::GetAdaptersInfo(pAdapterInfo,&ulLen) ==  ERROR_SUCCESS)
	{
		if(pAdapterInfo != NULL)
		{
			if(pMac!=NULL)
				memcpy(pMac, pAdapterInfo->Address, MAC_MAX_LENTH);
			if(pDevName!=NULL)
				strcpy(pDevName,pAdapterInfo->AdapterName);
			dwGateway = ::inet_addr(pAdapterInfo->GatewayList.IpAddress.String);
			dwIP = ::inet_addr(pAdapterInfo->IpAddressList.IpAddress.String);
			dwNetmask = ::inet_addr(pAdapterInfo->IpAddressList.IpMask.String);

			delete pAdapterInfo;
			return TRUE;
		}
	}
	delete pAdapterInfo;
	return FALSE;
}
//////遍历所有活动网卡
VOID FindAllAdapter()
{
	ULONG ulAdapterInfoSize = sizeof(IP_ADAPTER_INFO);
	IP_ADAPTER_INFO *pAdapterInfoBkp, *pAdapterInfo = (IP_ADAPTER_INFO*)new char[ulAdapterInfoSize];
	if( GetAdaptersInfo(pAdapterInfo, &ulAdapterInfoSize) == ERROR_BUFFER_OVERFLOW ) // 缓冲区不够大
	{
		delete pAdapterInfo;
		pAdapterInfo = (IP_ADAPTER_INFO*)new char[ulAdapterInfoSize];
		pAdapterInfoBkp = pAdapterInfo;
	}
	if( GetAdaptersInfo(pAdapterInfo, &ulAdapterInfoSize) == ERROR_SUCCESS )
	{
		do{
			if(pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET)	// 判断是否为以太网接口
			{
				printf("%s,%s",pAdapterInfo->Description,pAdapterInfo->AdapterName);

			}
			pAdapterInfo = pAdapterInfo->Next;
		}while(pAdapterInfo);
	}
	delete pAdapterInfoBkp;
}

#define IPTOSBUFFERS	6 
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;
	
	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

#endif
