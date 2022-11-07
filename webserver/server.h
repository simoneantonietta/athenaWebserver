#include <sys/stat.h>
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
#include "file.h"

/* Defines */
#define DHCP_OPTIONS 		"BOOTPROTO="
#define IP_STRING	 		"IP="
#define SUBNET_STRING	 	"NETMASK="
#define BROADCAST_STRING	"BROADCAST="
#define NETWORK_STRING		"NETWORK="
#define GATEWAY_STRING		"GATEWAY="

#define N_BYTES_PARAMS		4096

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
}ipFormValues_t;

typedef struct{
	char connection[4];				/* COM/USB/LAN */
	char serialPort;				/* 0=COM1, 1=COM2, 2=USB1, 3=USB2, 4=USB3 */
	unsigned int plant;
	unsigned int address;
	unsigned int baudrate;
	networkAddr ip;
	unsigned int networkPort;	
	unsigned int numeration;	
	char code[64];					/* for Tecnofire only */
	char passphrase[64];			/* for Tecnofire only */
	unsigned int registerDimension;	/* for DEF only */
	unsigned int polling;
}centralParam_t;

typedef struct{
	char centralType[64];
	char centralModel[64];
	centralParam_t centralParam;
}isiFormValues_t;

typedef struct{
	
}svFormValues_t;

typedef struct{
	char * username;
	char * oldPassword;
	char * newPassword;
	char * newPassword2;
}credentialFormValues_t;

/* Index */
void Log(char *filename, char *content);
int parseSystemForm(char* form, ipFormValues_t * result);
int parseCentralForm(char* form, isiFormValues_t * result);
int parseSupervisorForm(char* form, svFormValues_t * result);
int parseCredentialForm(char* form, credentialFormValues_t * result);
void changeIP(ipFormValues_t * networkParam);
void changeIsiConf(isiFormValues_t * networkParam);
void changeSV(svFormValues_t * networkParam);
int changeCredential(credentialFormValues_t * credentialParam);
void b64_encode(char *clrstr, char *b64dst);
void b64_decode(char *b64src, char *clrdst);
void fillPage(struct file_data *page, char *pageName);

/* Implementation */
void Log(char *filename, char *content)
{
	FILE * fd;
	char filenames[2][512];
	int size;
	struct stat st;
	time_t current_time;
	struct tm * tm_now;	
	char c_time_string[64];

	sprintf(filenames[0],"%s.0",filename);
	sprintf(filenames[1],"%s.1",filename);
	stat(filenames[0], &st);
	size = st.st_size;

	if(size > 45000)  
	{    
	char cmd[512*2+4];
	sprintf(cmd, "mv %s %s", filenames[0], filenames[1]);
	system(cmd);
	}

	current_time = time(NULL);	
	tm_now = localtime(&current_time);
	strftime(c_time_string,sizeof(c_time_string),"%d/%m/%y-%X",tm_now);

	fd = fopen(filenames[0],"a+");
	fprintf(fd, "%s:%s", c_time_string, content);
	fclose(fd);
}

int parseSystemForm(char* form, ipFormValues_t * result)
{
	unsigned int qty = 0, i, nParam=0;
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	printf("\nThere are %d Parameters\n",nParam);
	
	char *strValue, tmpValue[10];
	unsigned char valueLen;
	
	strValue = strstr(form,"ip1=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);	
		result->ip.addr1 = atoi(tmpValue);
	}
	strValue = strstr(form,"ip2=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);
		result->ip.addr2 = atoi(tmpValue);		
	}
	strValue = strstr(form,"ip3=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);
		result->ip.addr3 = atoi(tmpValue);		
	}	
	strValue = strstr(form,"ip4=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);
		result->ip.addr4 = atoi(tmpValue);		
	}	
	strValue = strstr(form,"sn1=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);	
		result->sn.addr1 = atoi(tmpValue);		
	}
	strValue = strstr(form,"sn2=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);
		result->sn.addr2 = atoi(tmpValue);		
	}	
	strValue = strstr(form,"sn3=");
	if(strValue != NULL)	
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);
		result->sn.addr3 = atoi(tmpValue);				
	}
	strValue = strstr(form,"sn4=");
	if(strValue != NULL)	
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);
		result->sn.addr4 = atoi(tmpValue);		
	}
	strValue = strstr(form,"gw1=");
	if(strValue != NULL)	
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);	
		result->gw.addr1 = atoi(tmpValue);
	}
	strValue = strstr(form,"gw2=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);
		result->gw.addr2 = atoi(tmpValue);		
	}
	strValue = strstr(form,"gw3=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);
		result->gw.addr3 = atoi(tmpValue);
	}	
	strValue = strstr(form,"gw4=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;
		strncpy(tmpValue,strValue+4,valueLen);
		result->gw.addr4 = atoi(tmpValue);				
	}
	if(strstr(form,"dhcpChk=on"))
		result->dhcp = 1;
	else if(strstr(form,"dhcpChk=off"))
		result->dhcp = 0;		


	char logString[256];
	sprintf(logString,"New network config:\nDHCP:%d\nIP:%d.%d.%d.%d\nSN:%d.%d.%d.%d\nGW:%d.%d.%d.%d\n",result->dhcp,
																		result->ip.addr1,result->ip.addr2,result->ip.addr3,result->ip.addr4,
																		result->sn.addr1,result->sn.addr2,result->sn.addr3,result->sn.addr4,
																		result->gw.addr1,result->gw.addr2,result->gw.addr3,result->gw.addr4);
	printf(logString);

    return qty;   
}

int parseCentralForm(char* form, isiFormValues_t * result)
{
	unsigned int qty = 0, i, nParam=0;
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	printf("\nThere are %d Parameters\n",nParam);
	
	char *strValue, tmpValue[64];
	unsigned char valueLen;
	
	strValue = strstr(form,"centralType=");
	if(strValue!=NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;	
		for(i=0;strValue[i+strlen("centralType=")]!='&';i++)
			result->centralType[i] = strValue[i+strlen("centralType=")];
		result->centralType[i] = '\0';
	}
	strValue = strstr(form,"centralModel=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;	
		for(i=0;strValue[i+strlen("centralModel=")]!='&';i++)
			result->centralModel[i] = strValue[i+strlen("centralModel=")];
		result->centralModel[i] = '\0';
	}
	
	if(strncmp(result->centralType,"notifier",strlen("notifier"))==0)			/* Consider only notifier params */
	{
		strValue = strstr(form,"notifierId=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("notifierId="),valueLen);
			result->centralParam.address = atoi(tmpValue);			
		}
		strValue = strstr(form,"notifierPolling=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("notifierPolling="),valueLen);
			result->centralParam.polling = atoi(tmpValue);
		}
		strValue = strstr(form,"notifierConnection=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;	
			for(i=0;strValue[i+strlen("notifierConnection=")]!='&';i++)
				result->centralParam.connection[i] = strValue[i+strlen("notifierConnection=")];
			result->centralParam.connection[i] = '\0';		
		}
		strValue = strstr(form,"isiPort=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;	
			for(i=0;strValue[i+strlen("isiPort=")]!='&';i++)
				tmpValue[i] = strValue[i+strlen("isiPort=")];
			tmpValue[i] = '\0';		
			if(strncmp(tmpValue,"com1",strlen("com1"))==0)
				result->centralParam.serialPort = 0;
			else if(strncmp(tmpValue,"com2",strlen("com2"))==0)
				result->centralParam.serialPort = 1;
			else if(strncmp(tmpValue,"usb1",strlen("usb1"))==0)
				result->centralParam.serialPort = 2;
			else if(strncmp(tmpValue,"usb2",strlen("usb2"))==0)
				result->centralParam.serialPort = 3;
			else if(strncmp(tmpValue,"usb3",strlen("usb3"))==0)
				result->centralParam.serialPort = 4;
		}
		strValue = strstr(form,"notifierIP1=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("notifierIP1="),valueLen);
			result->centralParam.ip.addr1 = atoi(tmpValue);
		}
		strValue = strstr(form,"notifierIP2=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("notifierIP2="),valueLen);
			result->centralParam.ip.addr2 = atoi(tmpValue);
		}
		strValue = strstr(form,"notifierIP3=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("notifierIP3="),valueLen);
			result->centralParam.ip.addr3 = atoi(tmpValue);
		}
		strValue = strstr(form,"notifierIP4=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("notifierIP4="),valueLen);			
			result->centralParam.ip.addr4 = atoi(tmpValue);			
		}
		strValue = strstr(form,"notifierPort=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("notifierPort="),valueLen);
			result->centralParam.networkPort = atoi(tmpValue);
		}
		strValue = strstr(form,"notifierBaudrate=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("notifierBaudrate="),valueLen);
			result->centralParam.baudrate = atoi(tmpValue);
		}
		strValue = strstr(form,"notifierNumeration=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("notifierNumeration="),valueLen);		
			for(i=0;strValue[i+strlen("notifierNumeration=")]!='&';i++)
				tmpValue[i] = strValue[i+strlen("notifierNumeration=")];
			tmpValue[i] = '\0';
			if(strncmp(tmpValue,"standard",strlen("standard"))==0)
				result->centralParam.numeration = 0;			
			else if(strncmp(tmpValue,"stdRiass",strlen("stdRiass"))==0)
				result->centralParam.numeration = 1;									
		}
	}
	else if(strncmp(result->centralType,"tecnofire",strlen("tecnofire"))==0)	/* Consider only tecnofire params */
	{
		strValue = strstr(form,"tecnofireCode=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;	
			for(i=0;strValue[i+strlen("tecnofireCode=")]!='&';i++)
				result->centralParam.code[i] = strValue[i+strlen("tecnofireCode=")];
			result->centralParam.code[i] = '\0';
		}
		strValue = strstr(form,"tecnofireIP1=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("tecnofireIP1="),valueLen);
			result->centralParam.ip.addr1 = atoi(tmpValue);
		}
		strValue = strstr(form,"tecnofireIP2=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("tecnofireIP2="),valueLen);
			result->centralParam.ip.addr2 = atoi(tmpValue);
		}
		strValue = strstr(form,"tecnofireIP3=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("tecnofireIP3="),valueLen);
			result->centralParam.ip.addr3 = atoi(tmpValue);
		}
		strValue = strstr(form,"tecnofireIP4=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("tecnofireIP4="),valueLen);
			result->centralParam.ip.addr4 = atoi(tmpValue);
		}
		strValue = strstr(form,"tecnofirePort=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("tecnofirePort="),valueLen);
			result->centralParam.networkPort = atoi(tmpValue);
		}
		strValue = strstr(form,"tecnofirePass=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;	
			for(i=0;strValue[i+strlen("tecnofirePass=")]!='&';i++)
				result->centralParam.passphrase[i] = strValue[i+strlen("tecnofirePass=")];
			result->centralParam.passphrase[i] = '\0';
		}
	}
	else if(strncmp(result->centralType,"honeywell",strlen("honeywell"))==0)	/* Consider only honeywell params */
	{

	}
	else if(strncmp(result->centralType,"def",strlen("def"))==0)				/* Consider only def params */
	{
		strValue = strstr(form,"defPlant=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("defPlant="),valueLen);		
			result->centralParam.plant = atoi(tmpValue);
		}
		strValue = strstr(form,"defId=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("defId="),valueLen);		
			result->centralParam.address = atoi(tmpValue);			
		}
		strValue = strstr(form,"defBaudrate=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("defBaudrate="),valueLen);		
			result->centralParam.baudrate = atoi(tmpValue);
		}
		strValue = strstr(form,"defMaxReg=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("defMaxReg="),valueLen);
			result->centralParam.registerDimension = atoi(tmpValue);
		}
		strValue = strstr(form,"defPolling=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("defPolling="),valueLen);
			result->centralParam.polling = atoi(tmpValue);
		}
	}
	else if(strncmp(result->centralType,"detfire",strlen("detfire"))==0)		/* Consider only detfire params */
	{
		strValue = strstr(form,"detfireAdd=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("detfireAdd="),valueLen);
			result->centralParam.address = atoi(tmpValue);
		}
		strValue = strstr(form,"detfireBaudrate=");
		if(strValue != NULL)
		{
			for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
				;
			strncpy(tmpValue,strValue+strlen("detfireBaudrate="),valueLen);		
			result->centralParam.baudrate = atoi(tmpValue);			
		}
	}

	char logString[256];
	sprintf(logString,"%s:%s\n",result->centralType,result->centralModel);
	printf(logString);
	Log("/tmp/webserver.log",logString);
	sprintf(logString,"New central config:\n\tconnection:%s\n\tserialPort:%d\n\tplant:%d\n\taddress:%d\n\tbaudrate:%d\n\tIP:%d.%d.%d.%d\n\tnetworkPort:%d\n\tnumeration:%d\n\tcode:%s\n\tpassphrase:%s\n\tregisterDimension:%d\n\tpolling:%d\n",
																		result->centralParam.connection,
																		result->centralParam.serialPort,
																		result->centralParam.plant,
																		result->centralParam.address,
																		result->centralParam.baudrate,																		
																		result->centralParam.ip.addr1,result->centralParam.ip.addr2,result->centralParam.ip.addr3,result->centralParam.ip.addr4,
																		result->centralParam.networkPort,
																		result->centralParam.numeration,
																		result->centralParam.code,
																		result->centralParam.passphrase,
																		result->centralParam.registerDimension,
																		result->centralParam.polling);
	printf(logString);
	Log("/tmp/webserver.log",logString);

    return qty;   
}

int parseSupervisorForm(char* form, svFormValues_t * result)
{
	unsigned int qty = 0, i, nParam=0;
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	printf("\nThere are %d Parameters\n",nParam);

	char *values = malloc(nParam*256*sizeof(char));
	
	char *strValue, tmpValue[10];
	unsigned char valueLen;
	
	strValue = strstr(form,"ip1=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;		
		strncpy(tmpValue,strValue+4,valueLen);
		//result->ip.addr1 = atoi(tmpValue);
	}

	free(values);

    return qty;   
}

int parseCredentialForm(char* form, credentialFormValues_t * result)
{
	unsigned int qty = 0, i, nParam=0;
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	printf("\nThere are %d Parameters\n",nParam);

	char *strValue, tmpValue[64];
	unsigned char valueLen;
	
	strValue = strstr(form,"oldPwd=");
	if(strValue != NULL)	
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;		
		strncpy(tmpValue,strValue+strlen("oldPwd="),valueLen-strlen("oldPwd="));			
		tmpValue[valueLen-strlen("oldPwd=")] = '\0';
		result->oldPassword = (char *)malloc(strlen(tmpValue)+1);
		strncpy(result->oldPassword,tmpValue,strlen(tmpValue));
		result->oldPassword[valueLen-strlen("oldPwd=")] = '\0';				
	}
	strValue = strstr(form,"newPwd=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;		
		strncpy(tmpValue,strValue+strlen("newPwd="),valueLen-strlen("newPwd="));
		tmpValue[valueLen-strlen("newPwd=")] = '\0';
		result->newPassword = (char *)malloc(strlen(tmpValue)+1);
		strncpy(result->newPassword,tmpValue,strlen(tmpValue));
		result->newPassword[valueLen-strlen("newPwd=")] = '\0';
	}
	strValue = strstr(form,"newPwd2=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;		
		strncpy(tmpValue,strValue+strlen("newPwd2="),valueLen-strlen("newPwd2="));
		tmpValue[valueLen-strlen("newPwd2=")] = '\0';
		result->newPassword2 = (char *)malloc(strlen(tmpValue)+1);
		strncpy(result->newPassword2,tmpValue,strlen(tmpValue));
		result->newPassword2[valueLen-strlen("newPwd2=")] = '\0';
	}
	strValue = strstr(form,"user=");
	if(strValue != NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;		
		strncpy(tmpValue,strValue+strlen("user="),valueLen-strlen("user="));
		tmpValue[valueLen-strlen("user=")] = '\0';
		result->username = (char *)malloc(strlen(tmpValue)+1);
		strncpy(result->username,tmpValue,strlen(tmpValue));
		result->username[valueLen-strlen("user=")] = '\0';
	}

	printf("Ho finito di parsificare le credenziali\n");
    return qty;   
}

void changeIP(ipFormValues_t * networkParam)
{
	FILE * fd = fopen("/etc/network/network.conf","r");
	//FILE * fd = fopen("/home/utente/network.conf","r");
	char ip[18], sn[18], gw[18], broadcast[18], network[18], dhcp[2][17], networkFile[30][100];
	int index = 0, i;

	if(fd != NULL)
	{
		
		sprintf(ip,"\"%d.%d.%d.%d\"",networkParam->ip.addr1, networkParam->ip.addr2, networkParam->ip.addr3, networkParam->ip.addr4);
		sprintf(sn,"\"%d.%d.%d.%d\"",networkParam->sn.addr1, networkParam->sn.addr2, networkParam->sn.addr3, networkParam->sn.addr4);
		sprintf(gw,"\"%d.%d.%d.%d\"",networkParam->gw.addr1, networkParam->gw.addr2, networkParam->gw.addr3, networkParam->gw.addr4);		
		sprintf(broadcast,"\"%d.%d.%d.%d\"",
							(networkParam->sn.addr1 & networkParam->ip.addr1), 
							(networkParam->sn.addr2 & networkParam->ip.addr2), 
							(networkParam->sn.addr3 & networkParam->ip.addr3), 
							(networkParam->sn.addr4 & networkParam->ip.addr4) | (0xFF ^ networkParam->sn.addr4));		
		sprintf(network,"\"%d.%d.%d.%d\"",
							(networkParam->sn.addr1 & networkParam->ip.addr1), 
							(networkParam->sn.addr2 & networkParam->ip.addr2), 
							(networkParam->sn.addr3 & networkParam->ip.addr3), 
							(networkParam->sn.addr4 & networkParam->ip.addr4));		
		sprintf(dhcp[0],"BOOTPROTO=\"none\"");
		sprintf(dhcp[1],"BOOTPROTO=\"dhcp\"");

		while(fgets(networkFile[index++],100,fd))
		{
			Log("/tmp/webserver.log",networkFile[index-1]);
			if(strncmp(networkFile[index-1],DHCP_OPTIONS,strlen(DHCP_OPTIONS))==0)
			{			
				sprintf(networkFile[index-1],"%s\n",dhcp[networkParam->dhcp]);			
			}
			else if(strncmp(networkFile[index-1],IP_STRING,strlen(IP_STRING))==0)
			{
				sprintf(strchr(networkFile[index-1], '"'),"%s\n",ip);			
			}
			else if(strncmp(networkFile[index-1],SUBNET_STRING,strlen(SUBNET_STRING))==0)
			{
				sprintf(strchr(networkFile[index-1], '"'),"%s\n",sn);			
			}
			else if(strncmp(networkFile[index-1],BROADCAST_STRING,strlen(BROADCAST_STRING))==0)
			{
				sprintf(strchr(networkFile[index-1], '"'),"%s\n", broadcast);				
			}
			else if(strncmp(networkFile[index-1],NETWORK_STRING,strlen(NETWORK_STRING))==0)
			{
				sprintf(strchr(networkFile[index-1], '"'),"%s\n", network);				
			}
			else if(strncmp(networkFile[index-1],GATEWAY_STRING,strlen(GATEWAY_STRING))==0)
			{
				sprintf(strchr(networkFile[index-1], '"'),"%s\n",gw);			
			}
		}

		fclose(fd);

		//fd = fopen("/home/utente/network.conf","w");	
		fd = fopen("/etc/network/network.conf","w");	
		if(fd != NULL)
		{
			for(i=0;i<index;i++)
				fwrite(networkFile[i],1,strlen(networkFile[i]),fd);

			fclose(fd);	
			system("reboot");
		}
		else
			printf("Errore apertura file network.conf in scrittura\n");
	}
	else
		printf("Errore apertura file network.conf in lettura\n");

}

void changeIsiConf(isiFormValues_t * isiParam)
{

}

void changeSV(svFormValues_t * svParam)
{

}

int changeCredential(credentialFormValues_t * credentialParam)
{
	unsigned int i;
	int returnVal = 0;
	FILE *fd = fopen("serverroot/pwd","r");
	char tmpString[256], username[64], password[64], index;
	
	fgets(tmpString,sizeof(tmpString),fd);
	fclose(fd);

	for(i=0;tmpString[i]!=':' && i<sizeof(username);i++)
		username[i] = tmpString[i];	
	username[i++] = '\0';
	index = i;
	while(tmpString[i]!='\n' && i<sizeof(username))
	{
		password[i-index] = tmpString[i];
		i++;
	}
	password[i-index] = '\0';

	if( (strcmp(credentialParam->username,username)==0)&&
		(strcmp(credentialParam->oldPassword,password)==0)&&
		(strcmp(credentialParam->newPassword,credentialParam->newPassword2)==0))
	{		
		printf("Sto cambiando credenziali\n");
		fd = fopen("serverroot/pwd","w");
		fprintf(fd,"%s:%s\n", username, credentialParam->newPassword);
		fclose(fd);
		returnVal = 1;
	}

	free(credentialParam->username);
	free(credentialParam->oldPassword);
	free(credentialParam->newPassword);
	free(credentialParam->newPassword2);

	return returnVal;
}


/* ---- Base64 Encoding/Decoding Table --- */
char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* decodeblock - decode 4 '6-bit' characters into 3 8-bit binary bytes */
void decodeblock(unsigned char in[], char *clrstr) {
	unsigned char out[4];
	out[0] = in[0] << 2 | in[1] >> 4;
	out[1] = in[1] << 4 | in[2] >> 2;
	out[2] = in[2] << 6 | in[3] >> 0;
	out[3] = '\0';
	strncat(clrstr, (char *)out, sizeof(out));
}

void b64_decode(char *b64src, char *clrdst) {
	int c, phase, i;
	unsigned char in[4];
	char *p;

	clrdst[0] = '\0';
	phase = 0; i=0;
	while(b64src[i]) {
		c = (int) b64src[i];
		if(c == '=') {
			decodeblock(in, clrdst); 
			break;
		}
		p = strchr(b64, c);
		if(p) {
			in[phase] = p - b64;
			phase = (phase + 1) % 4;
			if(phase == 0) {
				decodeblock(in, clrdst);
				in[0]=in[1]=in[2]=in[3]=0;
			}
		}
		i++;
	}
}

/* encodeblock - encode 3 8-bit binary bytes as 4 '6-bit' characters */
void encodeblock( unsigned char in[], char b64str[], int len ) {
	unsigned char out[5];
	out[0] = b64[ in[0] >> 2 ];
	out[1] = b64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
	out[2] = (unsigned char) (len > 1 ? b64[ ((in[1] & 0x0f) << 2) |
		((in[2] & 0xc0) >> 6) ] : '=');
	out[3] = (unsigned char) (len > 2 ? b64[ in[2] & 0x3f ] : '=');
	out[4] = '\0';
	strncat(b64str, (char *)out, sizeof(out));
}

/* encode - base64 encode a stream, adding padding if needed */
void b64_encode(char *clrstr, char *b64dst) {
	unsigned char in[3];
	int i, len = 0;
	int j = 0;

	b64dst[0] = '\0';
	while(clrstr[j]) {
		len = 0;
		for(i=0; i<3; i++) {
			in[i] = (unsigned char) clrstr[j];
			if(clrstr[j]) {
				len++; j++;
			}
			else in[i] = 0;
		}
		if( len ) {
			encodeblock( in, b64dst, len );
		}
	}
}

/* fill html page when the resource is requested by a host */
void fillPage(struct file_data *page, char *pageName)
{
	FILE * fd;
	char tmpString[100], *pageFilled, *pageCpy, *pageRow, addressString[22], paramFound=0;
	unsigned int networkParams[13];
	unsigned int idx=0, newPageIndex=0, i, old_pageRowIdx;
	int pageRowIdx;
	char networkParamList[13][7+1];

	strcpy(networkParamList[0],"dhcpChk");
	strcpy(networkParamList[1],"ip1");
	strcpy(networkParamList[2],"ip2");
	strcpy(networkParamList[3],"ip3");
	strcpy(networkParamList[4],"ip4");
	strcpy(networkParamList[5],"sn1");
	strcpy(networkParamList[6],"sn2");
	strcpy(networkParamList[7],"sn3");
	strcpy(networkParamList[8],"sn4");
	strcpy(networkParamList[9],"gw1");
	strcpy(networkParamList[10],"gw2");
	strcpy(networkParamList[11],"gw3");
	strcpy(networkParamList[12],"gw4");

	pageCpy = (char *)malloc(page->size);
	memcpy(pageCpy,page->data,page->size);
	pageFilled = malloc(page->size + N_BYTES_PARAMS);
	printf("Page size:%d\n",page->size);

	if(strncmp(pageName,"/parametri_di_centrale.html",strlen("parametri_di_centrale"))==0)
	{

	}
	else if(strncmp(pageName,"/parametri_di_sistema.html",strlen("parametri_di_sistema"))==0)
	{
		/* show network configuration */
		fd = fopen("/etc/network/network.conf", "r");
		while(fgets(tmpString,100,fd))
		{	
			if(strncmp(tmpString,DHCP_OPTIONS,strlen(DHCP_OPTIONS))==0)
			{			
				if(strstr(tmpString,"dhcp")!=NULL)
				{
					networkParams[0] = 1;
				}
				else
				{
					networkParams[0] = 0;
				}
			}
			else if(strncmp(tmpString,IP_STRING,strlen(IP_STRING))==0)
			{
				strtok(tmpString,"\"");
				networkParams[1] = atoi(strtok(NULL,"."));
				networkParams[2] = atoi(strtok(NULL,"."));
				networkParams[3] = atoi(strtok(NULL,"."));
				networkParams[4] = atoi(strtok(NULL,"\""));
			}
			else if(strncmp(tmpString,SUBNET_STRING,strlen(SUBNET_STRING))==0)
			{
				strtok(tmpString,"\"");
				networkParams[5] = atoi(strtok(NULL,"."));
				networkParams[6] = atoi(strtok(NULL,"."));
				networkParams[7] = atoi(strtok(NULL,"."));
				networkParams[8] = atoi(strtok(NULL,"\""));	
			}
			else if(strncmp(tmpString,GATEWAY_STRING,strlen(GATEWAY_STRING))==0)
			{
				strtok(tmpString,"\"");
				networkParams[9] = atoi(strtok(NULL,"."));
				networkParams[10] = atoi(strtok(NULL,"."));
				networkParams[11] = atoi(strtok(NULL,"."));
				networkParams[12] = atoi(strtok(NULL,"\""));
			}
		}
		fclose(fd);

		sprintf(tmpString,"DHCP:%d\tIP:%d.%d.%d.%d\tSN:%d.%d.%d.%d\tGW:%d.%d.%d.%d\n",networkParams[0],
																					  networkParams[1], networkParams[2], networkParams[3], networkParams[4],
																					  networkParams[5], networkParams[6], networkParams[7], networkParams[8],
																					  networkParams[9], networkParams[10], networkParams[11], networkParams[12]);
		Log("/tmp/webserver.log",tmpString);

		pageRowIdx=0;
		old_pageRowIdx=0;
		while(pageRowIdx<page->size)
		{			
			while(pageRowIdx<page->size && ((((char*)(page->data))[pageRowIdx])!='\n'))		// search next new line
				pageRowIdx++;
			if(pageRowIdx<page->size)														// new line found
			{				
				pageRow = malloc(pageRowIdx - old_pageRowIdx + 2);				
				memcpy(pageRow,page->data+old_pageRowIdx,pageRowIdx - old_pageRowIdx + 1);				
				memcpy(pageFilled+newPageIndex,pageRow,pageRowIdx - old_pageRowIdx + 1);				
				pageRow[pageRowIdx - old_pageRowIdx] = '\0';								// add terminator	

				i=0;
				while(i<13 && !paramFound)												// search network parameter rows 
				{					
					if(strstr(pageRow,networkParamList[i])!=NULL)
						paramFound = 1;					
					else
						i++;
				}
				if(paramFound)
				{
					paramFound = 0;
					for(idx=0;idx<strlen(pageRow) && (pageRow[idx]!='>');idx++)			// search end of input field
						;
					if(idx<strlen(pageRow))												// end of input field found
					{
						if(i!=0){
							sprintf(addressString," value=\"%d\">\n",networkParams[i]);					
							strncpy(pageFilled+newPageIndex+idx,addressString,strlen(addressString));							
							newPageIndex += idx+strlen(addressString);																
						}
						else															// dhcp
						{							
							if(networkParams[0] == 0)									// dhcp off
								sprintf(addressString," value=\"off\">\n");					
							else														// dhcp on
								sprintf(addressString," value=\"on\" checked>\n");					
							strncpy(pageFilled+newPageIndex+idx,addressString,strlen(addressString));
							newPageIndex += idx+strlen(addressString);												
						}		
					}
					else																// error, go on without changing the row
					{
						newPageIndex += pageRowIdx - old_pageRowIdx + 1;		
					}
				}
				else
				{					
						newPageIndex += pageRowIdx - old_pageRowIdx + 1;					
				}
				if(pageRow != NULL)	
					free(pageRow);

				old_pageRowIdx = ++pageRowIdx;
			}
		}
		*(pageFilled+newPageIndex) = '\0';
		free(page->data);
		page->data = malloc(strlen(pageFilled));
		memcpy((char *)(page->data),pageFilled,strlen(pageFilled));
		page->size = strlen(pageFilled);	
	}
	else if(strncmp(pageName,"/parametri_di_supervisione.html",strlen("parametri_di_supervisione"))==0)
	{

	}

	if(pageFilled != NULL)
		free(pageFilled);
	if(pageCpy != NULL)
		free(pageCpy);
}
/* */
