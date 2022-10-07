#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/file.h>
#include <fcntl.h>

/* Defines */
#define DHCP_OPTIONS 		"BOOTPROTO="
#define IP_STRING	 		"IP="
#define SUBNET_STRING	 	"NETMASK="
#define BROADCAST_STRING	"BROADCAST="
#define NETWORK_STRING		"NETWORK="
#define GATEWAY_STRING		"GATEWAY="

/* Variables */
typedef struct{
    int addr1;
    int addr2;
    int addr3;
    int addr4;
}networkAddr;

typedef struct{
	int dhcp;
    networkAddr ip;
    networkAddr sn;
    networkAddr gw;
}formValues;


/* Index */
void Log(char *filename, char *content);
int parseForm(char* form, formValues * result);
void changeIP(formValues * networkParam);


/* Implementation */
void Log(char *filename, char *content)
{
	FILE * fd = fopen(filename, "a+");
	fprintf(fd, "%s\n", content);
	fclose(fd);
}

int parseForm(char* form, formValues * result)
{
	unsigned int qty = 0, i, nParam=0;
	const char delimiter[2] = "&";
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	printf("\nThere are %d Parameters\n",nParam);

	char *values = malloc(nParam*256*sizeof(char));
	
	char *strValue, tmpValue[10], valueLen;
	
	strValue = strstr(form,"ip1=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->ip.addr1 = atoi(tmpValue);
	strValue = strstr(form,"ip2=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->ip.addr2 = atoi(tmpValue);
	strValue = strstr(form,"ip3=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->ip.addr3 = atoi(tmpValue);
	strValue = strstr(form,"ip4=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->ip.addr4 = atoi(tmpValue);
	strValue = strstr(form,"sn1=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->sn.addr1 = atoi(tmpValue);
	strValue = strstr(form,"sn2=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->sn.addr2 = atoi(tmpValue);
	strValue = strstr(form,"sn3=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)	
		result->sn.addr3 = atoi(tmpValue);		
	strValue = strstr(form,"sn4=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)	
		result->sn.addr4 = atoi(tmpValue);
	strValue = strstr(form,"gw1=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)	
		result->gw.addr1 = atoi(tmpValue);
	strValue = strstr(form,"gw2=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->gw.addr2 = atoi(tmpValue);
	strValue = strstr(form,"gw3=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->gw.addr3 = atoi(tmpValue);
	strValue = strstr(form,"gw4=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->gw.addr4 = atoi(tmpValue);		
	if(strstr(form,"dhcp=on"))
		result->dhcp = 1;
	else if(strstr(form,"dhcp=off"))
		result->dhcp = 0;		


	char logString[256];
	sprintf(logString,"New network config:\nDHCP:%d\nIP:%d.%d.%d.%d\nSN:%d.%d.%d.%d\nGW:%d.%d.%d.%d\n",result->dhcp,
																		result->ip.addr1,result->ip.addr2,result->ip.addr3,result->ip.addr4,
																		result->sn.addr1,result->sn.addr2,result->sn.addr3,result->sn.addr4,
																		result->gw.addr1,result->gw.addr2,result->gw.addr3,result->gw.addr4);

	free(values);

    return qty;   
}

void changeIP(formValues * networkParam)
{
	//FILE * fd = fopen("/etc/network/network.conf","r");
	FILE * fd = fopen("/home/utente/network.conf","r");
	char ip[16], sn[16], gw[16], networkFile[20][50];
	int index = 0, i;

	sprintf(ip,"\"%d.%d.%d.%d\"",networkParam->ip.addr1, networkParam->ip.addr2, networkParam->ip.addr3, networkParam->ip.addr4);
	sprintf(sn,"\"%d.%d.%d.%d\"",networkParam->sn.addr1, networkParam->sn.addr2, networkParam->sn.addr3, networkParam->sn.addr4);
	sprintf(gw,"\"%d.%d.%d.%d\"",networkParam->gw.addr1, networkParam->gw.addr2, networkParam->gw.addr3, networkParam->gw.addr4);

	while(fgets(networkFile[index++],50,fd))
	{
		Log("/tmp/webserver.log",networkFile[index-1]);
		if(strncmp(networkFile[index-1],DHCP_OPTIONS,strlen(DHCP_OPTIONS))==0)
		{
			
		}
		else if(strncmp(networkFile[index-1],IP_STRING,strlen(IP_STRING))==0)
		{
			strncpy(strchr(networkFile[index-1], '"'),ip,strlen(ip));
		}
		else if(strncmp(networkFile[index-1],SUBNET_STRING,strlen(SUBNET_STRING))==0)
		{
			strncpy(strchr(networkFile[index-1], '"'),sn,strlen(sn));
		}
		else if(strncmp(networkFile[index-1],BROADCAST_STRING,strlen(BROADCAST_STRING))==0)
		{
			
		}
		else if(strncmp(networkFile[index-1],NETWORK_STRING,strlen(NETWORK_STRING))==0)
		{

		}
		else if(strncmp(networkFile[index-1],GATEWAY_STRING,strlen(GATEWAY_STRING))==0)
		{
			strncpy(strchr(networkFile[index-1], '"'),gw,strlen(gw));
		}
	}

	fclose(fd);


	fd = fopen("/home/utente/network.conf","w");	

	for(i=0;i<index;i++)
		fwrite(networkFile[i],1,strlen(networkFile[i]),fd);

	fclose(fd);
}

/* */
